const { Client, GatewayIntentBits, Partials, Collection, EmbedBuilder, PermissionFlagsBits, ActivityType, AuditLogEvent } = require('discord.js');
const { REST } = require('@discordjs/rest');
const { Routes } = require('discord-api-types/v10');

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.GuildBans,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildWebhooks,
    GatewayIntentBits.GuildIntegrations,
  ],
  partials: [Partials.Channel, Partials.Message, Partials.GuildMember],
});

// ─── CONFIG ─────────────────────────────────────────────────────────────────
const config = {
  token: process.env.DISCORD_TOKEN || 'YOUR_BOT_TOKEN',
  prefix: '!',

  // Anti-Raid thresholds
  joinRateLimit: 10,           // max joins per window
  joinRateWindow: 10000,       // window in ms (10 seconds)
  newAccountAge: 3,            // days — flag accounts newer than this
  newAccountKick: false,       // auto-kick new accounts? OFF by default (safe for TikTok followers)

  // Anti-Nuke thresholds (per minute)
  maxChannelDeletes: 3,
  maxRoleDeletes: 3,
  maxBans: 5,
  maxKicks: 5,
  maxWebhookCreates: 3,

  // Anti-Spam thresholds
  maxMessagesPerWindow: 5,       // max identical/invite messages before action
  spamWindow: 5000,              // 5 seconds window
  maxInviteSpam: 2,              // max discord invite links before action
  spamMuteDuration: 10 * 60,    // mute duration in seconds (10 mins)

  // Log channel name (auto-detected if exists)
  logChannelName: 'mod-logs',

  // Bot bio / status messages (rotates every 30s)
  statuses: [
    { name: '🛡️ Protecting the server', type: ActivityType.Watching },
    { name: '⚡ Anti-Raid Active', type: ActivityType.Playing },
    { name: '🔒 Anti-Nuke Active', type: ActivityType.Playing },
    { name: '/help for commands', type: ActivityType.Listening },
  ],
};

// ─── STATE ───────────────────────────────────────────────────────────────────
const joinLog = new Map();           // guildId → [timestamps]
const actionLog = new Map();         // guildId → { type → [timestamps] }
const raidMode = new Map();          // guildId → boolean
const whitelist = new Map();         // guildId → Set<userId>
const antiNukeEnabled = new Map();   // guildId → boolean
const antiRaidEnabled = new Map();   // guildId → boolean
const spamTracker = new Map();       // userId → { msgs: [timestamps], invites: [timestamps] }
const mutedUsers = new Map();        // userId → timeout
const antiSpamEnabled = new Map();   // guildId → boolean

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function getLogChannel(guild) {
  return guild.channels.cache.find(
    c => c.name === config.logChannelName && c.isTextBased()
  );
}

async function sendLog(guild, embed) {
  let ch = getLogChannel(guild);
  if (!ch) ch = await ensureModLogsChannel(guild);
  if (ch) await ch.send({ embeds: [embed] }).catch(() => {});
}

function isWhitelisted(guild, userId) {
  return whitelist.get(guild.id)?.has(userId) || false;
}

function getActions(guildId, type) {
  if (!actionLog.has(guildId)) actionLog.set(guildId, {});
  const g = actionLog.get(guildId);
  if (!g[type]) g[type] = [];
  const now = Date.now();
  g[type] = g[type].filter(t => now - t < 60000);
  return g[type];
}

function trackAction(guildId, type) {
  getActions(guildId, type).push(Date.now());
}

function isAntiNukeEnabled(guildId) {
  return antiNukeEnabled.get(guildId) !== false; // default ON
}

function isAntiRaidEnabled(guildId) {
  return antiRaidEnabled.get(guildId) !== false; // default ON
}

async function punishNuker(guild, userId, reason) {
  if (isWhitelisted(guild, userId)) return;
  try {
    const member = await guild.members.fetch(userId).catch(() => null);
    if (!member) return;
    if (member.permissions.has(PermissionFlagsBits.Administrator)) return; // skip admins/owner

    await member.ban({ reason: `[Anti-Nuke] ${reason}`, deleteMessageSeconds: 0 });

    const embed = new EmbedBuilder()
      .setColor(0xff0000)
      .setAuthor({ name: '⬡  anti-nuke triggered' })
      .setDescription('```diff\n-  nuke attempt detected & neutralized\n```')
      .addFields(
        { name: 'user',   value: `<@${userId}> · \`${userId}\``, inline: true },
        { name: 'reason', value: reason, inline: true },
        { name: 'action', value: '```diff\n-  banned\n```', inline: true },
      )
      .setFooter({ text: 'guardbot  ·  anti-nuke' })
      .setTimestamp();
    await sendLog(guild, embed);
  } catch (e) {
    console.error('punishNuker error:', e);
  }
}

// ─── ANTI-SPAM: Invite links & message spam ───────────────────────────────────
const INVITE_REGEX = /(discord\.gg|discord\.com\/invite|discordapp\.com\/invite)\/[a-zA-Z0-9]+/gi;
const URL_REGEX = /https?:\/\/[^\s]+/gi;

client.on('messageCreate', async message => {
  if (!message.guild) return;
  if (message.author.bot) return;
  if (isWhitelisted(message.guild, message.author.id)) return;
  if (antiSpamEnabled.get(message.guild.id) === false) return; // default ON

  // Skip admins and moderators
  const member = message.member;
  if (!member) return;
  if (member.permissions.has(PermissionFlagsBits.ManageMessages)) return;

  const content = message.content;
  const userId = message.author.id;
  const guildId = message.guild.id;
  const now = Date.now();

  // Init tracker for this user
  if (!spamTracker.has(userId)) spamTracker.set(userId, { msgs: [], invites: [] });
  const tracker = spamTracker.get(userId);

  // Clean old entries
  tracker.msgs = tracker.msgs.filter(t => now - t < config.spamWindow);
  tracker.invites = tracker.invites.filter(t => now - t < config.spamWindow);

  // ── Check for Discord invite links ─────────────────────────────────────────
  const inviteMatches = content.match(INVITE_REGEX);
  if (inviteMatches) {
    tracker.invites.push(now);

    // Delete the message immediately
    await message.delete().catch(() => {});

    if (tracker.invites.length >= config.maxInviteSpam) {
      // Timeout / mute the user
      await muteUser(message.guild, member, `Invite link spam (${tracker.invites.length} invite links in ${config.spamWindow / 1000}s)`);
      tracker.invites = []; // reset
    } else {
      // First offense — just warn
      const warn = await message.channel.send({
        content: `<@${userId}> ⚠️ **No advertising!** Sending Discord invite links is not allowed.`
      }).catch(() => null);
      if (warn) setTimeout(() => warn.delete().catch(() => {}), 5000);
    }

    const embed = new EmbedBuilder()
      .setColor(0xff6600)
      .setAuthor({ name: '⬡  anti-spam  ·  invite link detected' })
      .addFields(
        { name: 'user',      value: `<@${userId}> · \`${userId}\``, inline: true },
        { name: 'channel',   value: `<#${message.channel.id}>`, inline: true },
        { name: 'link',      value: `\`${inviteMatches.join(', ').slice(0, 200)}\``, inline: false },
        { name: 'offense',   value: `#${tracker.invites.length + 1}`, inline: true },
        { name: 'action',    value: tracker.invites.length >= config.maxInviteSpam ? '```diff\n-  muted 10 mins\n```' : '```diff\n-  message deleted\n```', inline: true },
      )
      .setFooter({ text: 'guardbot  ·  anti-spam' })
      .setTimestamp();
    await sendLog(message.guild, embed);
    return;
  }

  // ── Check for message spam (same message repeated fast) ────────────────────
  tracker.msgs.push(now);
  if (tracker.msgs.length >= config.maxMessagesPerWindow) {
    await message.delete().catch(() => {});
    await muteUser(message.guild, member, `Message spam (${tracker.msgs.length} messages in ${config.spamWindow / 1000}s)`);
    tracker.msgs = [];

    const embed = new EmbedBuilder()
      .setColor(0xff0000)
      .setAuthor({ name: '⬡  anti-spam  ·  message spam detected' })
      .addFields(
        { name: 'user',     value: `<@${userId}> · \`${userId}\``, inline: true },
        { name: 'channel',  value: `<#${message.channel.id}>`, inline: true },
        { name: 'count',    value: `${tracker.msgs.length + 1} msgs / ${config.spamWindow / 1000}s`, inline: true },
        { name: 'action',   value: '```diff\n-  muted 10 mins\n```', inline: true },
      )
      .setFooter({ text: 'guardbot  ·  anti-spam' })
      .setTimestamp();
    await sendLog(message.guild, embed);
  }
});

// ─── MUTE HELPER ─────────────────────────────────────────────────────────────
async function muteUser(guild, member, reason) {
  try {
    // Use Discord timeout (communication disabled)
    const until = new Date(Date.now() + config.spamMuteDuration * 1000);
    await member.timeout(config.spamMuteDuration * 1000, `[Anti-Spam] ${reason}`);

    const warn = await guild.channels.cache
      .filter(c => c.isTextBased() && !c.name.includes('mod-logs') && !c.name.includes('staff'))
      .first()
      ?.send({ content: `🔇 <@${member.id}> has been **muted for 10 minutes** for: ${reason}` })
      .catch(() => null);
    if (warn) setTimeout(() => warn?.delete().catch(() => {}), 8000);

    const embed = new EmbedBuilder()
      .setColor(0xff0000)
      .setAuthor({ name: '⬡  user muted' })
      .addFields(
        { name: 'user',       value: `<@${member.id}> · \`${member.id}\``, inline: true },
        { name: 'reason',     value: reason, inline: true },
        { name: 'duration',   value: `${config.spamMuteDuration / 60} minutes`, inline: true },
        { name: 'unmuted at', value: until.toLocaleString(), inline: false },
      )
      .setFooter({ text: 'guardbot  ·  anti-spam' })
      .setTimestamp();
    await sendLog(guild, embed);
  } catch (e) {
    console.error('muteUser error:', e);
  }
}




client.on('guildMemberAdd', async member => {
  if (!isAntiRaidEnabled(member.guild.id)) return;

  const guildId = member.guild.id;
  const now = Date.now();

  // Track joins
  if (!joinLog.has(guildId)) joinLog.set(guildId, []);
  const joins = joinLog.get(guildId);
  joins.push(now);
  // Clean old
  const recent = joins.filter(t => now - t < config.joinRateWindow);
  joinLog.set(guildId, recent);

  // Flag new accounts
  const accountAge = (now - member.user.createdTimestamp) / 86400000;
  const isNewAccount = accountAge < config.newAccountAge;

  // Activate raid mode if threshold hit
  if (recent.length >= config.joinRateLimit) {
    raidMode.set(guildId, true);

    const embed = new EmbedBuilder()
      .setColor(0xff0000)
      .setAuthor({ name: '⬡  ⚠  raid mode activated' })
      .setDescription(`\`\`\`diff\n-  ${recent.length} joins detected in ${config.joinRateWindow / 1000}s\n-  all new joins will be kicked\n\`\`\``)
      .setFooter({ text: 'guardbot  ·  anti-raid' })
      .setTimestamp();
    await sendLog(member.guild, embed);
  }

  if (raidMode.get(guildId)) {
    await member.kick('[Anti-Raid] Raid mode active').catch(() => {});

    const embed = new EmbedBuilder()
      .setColor(0xff6600)
      .setAuthor({ name: '⬡  anti-raid  ·  member kicked' })
      .addFields(
        { name: 'user',        value: `${member.user.tag} · \`${member.id}\``, inline: true },
        { name: 'account age', value: `${accountAge.toFixed(1)} days`, inline: true },
        { name: 'new account', value: isNewAccount ? '```diff\n-  yes  ⚠\n```' : '```diff\n+  no\n```', inline: true },
      )
      .setFooter({ text: 'guardbot  ·  anti-raid' })
      .setTimestamp();
    await sendLog(member.guild, embed);
    return;
  }

  // Warn about new accounts even outside raid mode
  if (isNewAccount) {
    // Only kick new accounts if newAccountKick is explicitly ON
    // Default is OFF so TikTok followers (who may have new accounts) can join safely
    if (config.newAccountKick && !isWhitelisted(member.guild, member.id)) {
      await member.kick('[Anti-Raid] New account — too young').catch(() => {});
      const embed = new EmbedBuilder()
        .setColor(0xff6600)
        .setAuthor({ name: '⬡  anti-raid  ·  new account kicked' })
        .addFields(
          { name: 'user',        value: `${member.user.tag} · \`${member.id}\``, inline: true },
          { name: 'account age', value: `${accountAge.toFixed(1)} days`, inline: true },
          { name: 'reason',      value: 'account too new (auto-kick enabled)', inline: false },
        )
        .setFooter({ text: 'guardbot  ·  anti-raid  ·  use /newacckick off to allow new accounts' })
        .setTimestamp();
      await sendLog(member.guild, embed);
      return;
    }

    // Just flag/log — don't kick
    const embed = new EmbedBuilder()
      .setColor(0xff6600)
      .setAuthor({ name: '⬡  new account joined  ·  flagged (not kicked)' })
      .addFields(
        { name: 'user',        value: `${member.user.tag} · \`${member.id}\``, inline: true },
        { name: 'account age', value: `${accountAge.toFixed(1)} days`, inline: true },
        { name: 'note',        value: 'use `/newacckick on` to auto-kick new accounts', inline: false },
      )
      .setFooter({ text: 'guardbot  ·  anti-raid' })
      .setTimestamp();
    await sendLog(member.guild, embed);
  }
});

// ─── ANTI-NUKE: Channel deletes ──────────────────────────────────────────────
client.on('channelDelete', async channel => {
  if (!channel.guild) return;
  if (!isAntiNukeEnabled(channel.guild.id)) return;

  const entry = await channel.guild.fetchAuditLogs({ type: AuditLogEvent.ChannelDelete, limit: 1 }).catch(() => null);
  const executor = entry?.entries?.first()?.executor;
  if (!executor) return;

  trackAction(channel.guild.id, 'channelDelete');
  const actions = getActions(channel.guild.id, 'channelDelete');

  if (actions.length >= config.maxChannelDeletes) {
    await punishNuker(channel.guild, executor.id, `Mass channel deletion (${actions.length} channels deleted)`);
  }
});

// ─── ANTI-NUKE: Role deletes ─────────────────────────────────────────────────
client.on('roleDelete', async role => {
  if (!isAntiNukeEnabled(role.guild.id)) return;

  const entry = await role.guild.fetchAuditLogs({ type: AuditLogEvent.RoleDelete, limit: 1 }).catch(() => null);
  const executor = entry?.entries?.first()?.executor;
  if (!executor) return;

  trackAction(role.guild.id, 'roleDelete');
  const actions = getActions(role.guild.id, 'roleDelete');

  if (actions.length >= config.maxRoleDeletes) {
    await punishNuker(role.guild, executor.id, `Mass role deletion (${actions.length} roles deleted)`);
  }
});

// ─── ANTI-NUKE: Mass bans ────────────────────────────────────────────────────
client.on('guildBanAdd', async ban => {
  if (!isAntiNukeEnabled(ban.guild.id)) return;

  const entry = await ban.guild.fetchAuditLogs({ type: AuditLogEvent.MemberBanAdd, limit: 1 }).catch(() => null);
  const executor = entry?.entries?.first()?.executor;
  if (!executor) return;

  trackAction(ban.guild.id, 'ban');
  const actions = getActions(ban.guild.id, 'ban');

  if (actions.length >= config.maxBans) {
    await punishNuker(ban.guild, executor.id, `Mass banning (${actions.length} bans in 1 minute)`);
  }
});

// ─── ANTI-NUKE: Mass kicks ───────────────────────────────────────────────────
client.on('guildMemberRemove', async member => {
  if (!isAntiNukeEnabled(member.guild.id)) return;

  const entry = await member.guild.fetchAuditLogs({ type: AuditLogEvent.MemberKick, limit: 1 }).catch(() => null);
  const log = entry?.entries?.first();
  if (!log || log.target?.id !== member.id) return;
  const executor = log.executor;
  if (!executor) return;

  trackAction(member.guild.id, 'kick');
  const actions = getActions(member.guild.id, 'kick');

  if (actions.length >= config.maxKicks) {
    await punishNuker(member.guild, executor.id, `Mass kicking (${actions.length} kicks in 1 minute)`);
  }
});

// ─── ANTI-NUKE: Webhook spam ─────────────────────────────────────────────────
client.on('webhooksUpdate', async channel => {
  if (!isAntiNukeEnabled(channel.guild.id)) return;

  const entry = await channel.guild.fetchAuditLogs({ type: AuditLogEvent.WebhookCreate, limit: 1 }).catch(() => null);
  const executor = entry?.entries?.first()?.executor;
  if (!executor) return;

  trackAction(channel.guild.id, 'webhook');
  const actions = getActions(channel.guild.id, 'webhook');

  if (actions.length >= config.maxWebhookCreates) {
    await punishNuker(channel.guild, executor.id, `Mass webhook creation (${actions.length} webhooks)`);
  }
});

// ─── SLASH COMMANDS ──────────────────────────────────────────────────────────
const commands = [
  {
    name: 'help',
    description: '📋 Show all bot commands and info',
  },
  {
    name: 'newacckick',
    description: '🔞 Toggle auto-kick for new accounts (default: OFF — safe for TikTok followers)',
    options: [{
      name: 'toggle',
      description: 'Enable or disable',
      type: 3, required: true,
      choices: [{ name: 'Enable', value: 'on' }, { name: 'Disable', value: 'off' }]
    }]
  },
  {
    name: 'antispam',
    description: '🚫 Toggle Anti-Spam protection (invite links & message spam)',
    options: [{
      name: 'toggle',
      description: 'Enable or disable',
      type: 3, required: true,
      choices: [{ name: 'Enable', value: 'on' }, { name: 'Disable', value: 'off' }]
    }]
  },
  {
    name: 'antinuke',
    description: '🔒 Toggle Anti-Nuke protection',
    options: [{
      name: 'toggle',
      description: 'Enable or disable',
      type: 3, required: true,
      choices: [{ name: 'Enable', value: 'on' }, { name: 'Disable', value: 'off' }]
    }]
  },
  {
    name: 'antiraid',
    description: '🛡️ Toggle Anti-Raid protection',
    options: [{
      name: 'toggle',
      description: 'Enable or disable',
      type: 3, required: true,
      choices: [{ name: 'Enable', value: 'on' }, { name: 'Disable', value: 'off' }]
    }]
  },
  {
    name: 'raidmode',
    description: '🚨 Manually toggle raid mode (kicks all new joins)',
    options: [{
      name: 'toggle',
      description: 'Enable or disable',
      type: 3, required: true,
      choices: [{ name: 'Enable', value: 'on' }, { name: 'Disable', value: 'off' }]
    }]
  },
  {
    name: 'whitelist',
    description: '✅ Whitelist a user from anti-nuke actions',
    options: [{
      name: 'user',
      description: 'User to whitelist',
      type: 6, required: true
    }]
  },
  {
    name: 'unwhitelist',
    description: '❌ Remove a user from the whitelist',
    options: [{
      name: 'user',
      description: 'User to remove',
      type: 6, required: true
    }]
  },
  {
    name: 'status',
    description: '📊 Show current protection status',
  },
  {
    name: 'bio',
    description: '🤖 About this bot',
  },
];

// ─── AUTO-CREATE PRIVATE #mod-logs ───────────────────────────────────────────
async function ensureModLogsChannel(guild) {
  let ch = guild.channels.cache.find(c => c.name === config.logChannelName && c.isTextBased());
  if (ch) {
    // Make sure it's private (deny @everyone view)
    await ch.permissionOverwrites.edit(guild.roles.everyone, { ViewChannel: false }).catch(() => {});
    return ch;
  }

  // Create it if it doesn't exist
  ch = await guild.channels.create({
    name: config.logChannelName,
    type: 0, // GUILD_TEXT
    permissionOverwrites: [
      {
        id: guild.roles.everyone.id,
        deny: ['ViewChannel'],
      },
      {
        id: guild.members.me.id,
        allow: ['ViewChannel', 'SendMessages', 'EmbedLinks'],
      },
    ],
    topic: '⬡ private security logs  ·  guardbot',
    reason: 'GuardBot: auto-created private mod-logs channel',
  }).catch(() => null);

  return ch;
}

// ─── READY ───────────────────────────────────────────────────────────────────
client.once('ready', async () => {
  console.log(`✅ Logged in as ${client.user.tag}`);

  // Ensure private mod-logs exists in every guild
  for (const guild of client.guilds.cache.values()) {
    await ensureModLogsChannel(guild);
  }

  // Set bio / presence rotation
  let i = 0;
  const rotate = () => {
    const s = config.statuses[i % config.statuses.length];
    client.user.setPresence({ activities: [{ name: s.name, type: s.type }], status: 'online' });
    i++;
  };
  rotate();
  setInterval(rotate, 30000);

  // Register slash commands globally
  const rest = new REST({ version: '10' }).setToken(config.token);
  try {
    await rest.put(Routes.applicationCommands(client.user.id), { body: commands });
    console.log('✅ Slash commands registered');
  } catch (e) {
    console.error('Failed to register commands:', e);
  }
});

// ─── INTERACTION HANDLER ─────────────────────────────────────────────────────
client.on('interactionCreate', async interaction => {
  if (!interaction.isChatInputCommand()) return;

  const { commandName, guild, member } = interaction;
  const isAdmin = member?.permissions?.has(PermissionFlagsBits.Administrator);

  // /help
  if (commandName === 'help') {
    const embed = new EmbedBuilder()
      .setColor(0x1a1a2e)
      .setAuthor({ name: '✦ guardbot  ·  command list', iconURL: client.user.displayAvatarURL() })
      .setDescription('```\n  24/7 server protection against raids,\n  nukes, and spam.\n```')
      .addFields(
        { name: '⬡  anti-nuke', value: '`/antinuke on|off`\n`/whitelist @user`\n`/unwhitelist @user`', inline: true },
        { name: '⬡  anti-raid', value: '`/antiraid on|off`\n`/raidmode on|off`\n`/newacckick on|off` — auto-kick new accounts', inline: true },
        { name: '⬡  anti-spam', value: '`/antispam on|off`', inline: true },
        { name: '⬡  info', value: '`/status`  ·  `/bio`  ·  `/help`', inline: false },
        { name: '⬡  thresholds', value: `raid  ·  **${config.joinRateLimit} joins** / ${config.joinRateWindow / 1000}s\nnuke  ·  **${config.maxBans} bans**  ·  **${config.maxChannelDeletes} ch-dels**  ·  **${config.maxRoleDeletes} role-dels** / min\nspam  ·  **${config.maxInviteSpam} invite links** / ${config.spamWindow / 1000}s`, inline: false },
      )
      .setFooter({ text: 'admin permission required for all toggle commands' })
      .setTimestamp();
    return interaction.reply({ embeds: [embed] });
  }

  // /bio
  if (commandName === 'bio') {
    const embed = new EmbedBuilder()
      .setColor(0x1a1a2e)
      .setAuthor({ name: '✦ guardbot  ·  about', iconURL: client.user.displayAvatarURL() })
      .setThumbnail(client.user.displayAvatarURL())
      .setDescription('```\n  24/7 security bot — protecting discord\n  servers from raids, nukes & spam.\n```')
      .addFields(
        { name: '⬡  anti-raid', value: 'detects mass join floods & new accounts.\nauto-kicks during active raids.', inline: true },
        { name: '⬡  anti-nuke', value: 'monitors mass bans, kicks, deletions\n& webhook abuse. bans attackers instantly.', inline: true },
        { name: '⬡  anti-spam', value: 'deletes invite links & times out\nspammers automatically.', inline: true },
        { name: '⬡  whitelist', value: 'trusted admins bypass all detection.', inline: true },
        { name: '⬡  24/7 online', value: 'runs continuously with rotating status.', inline: true },
        { name: '⬡  version', value: '1.0.0  ·  discord.js v14', inline: true },
      )
      .setFooter({ text: 'guardbot  ·  always watching' })
      .setTimestamp();
    return interaction.reply({ embeds: [embed] });
  }

  // /status
  if (commandName === 'status') {
    const raidEnabled = isAntiRaidEnabled(guild.id);
    const nukeEnabled = isAntiNukeEnabled(guild.id);
    const spamEnabled = antiSpamEnabled.get(guild.id) !== false;
    const inRaid = raidMode.get(guild.id) || false;
    const wl = whitelist.get(guild.id) || new Set();

    const embed = new EmbedBuilder()
      .setColor(inRaid ? 0xff0000 : 0x1a1a2e)
      .setAuthor({ name: `✦ guardbot  ·  protection status${inRaid ? '  ·  ⚠ raid mode active' : ''}`, iconURL: client.user.displayAvatarURL() })
      .setDescription(inRaid ? '```\n  ⚠  raid mode is currently active!\n  new joins are being kicked.\n```' : '```\n  all systems operational.\n```')
      .addFields(
        { name: '⬡  anti-raid',  value: raidEnabled  ? '```diff\n+ enabled\n```' : '```diff\n- disabled\n```', inline: true },
        { name: '⬡  anti-nuke',  value: nukeEnabled  ? '```diff\n+ enabled\n```' : '```diff\n- disabled\n```', inline: true },
        { name: '⬡  anti-spam',  value: spamEnabled  ? '```diff\n+ enabled\n```' : '```diff\n- disabled\n```', inline: true },
        { name: '⬡  raid mode',  value: inRaid ? '```diff\n- active\n```' : '```diff\n+ inactive\n```', inline: true },
        { name: '⬡  new acc kick', value: config.newAccountKick ? '```diff\n- on (kicking new accs)\n```' : '```diff\n+ off (followers can join)\n```', inline: true },
        { name: '⬡  whitelist',  value: wl.size > 0 ? [...wl].map(id => `<@${id}>`).join(' · ') : 'none', inline: false },
      )
      .setFooter({ text: `guardbot  ·  ${guild.name}` })
      .setTimestamp();
    return interaction.reply({ embeds: [embed] });
  }

  // Admin-only commands below
  if (!isAdmin) {
    return interaction.reply({ content: '❌ You need **Administrator** permission to use this command.', ephemeral: true });
  }

  // /newacckick
  if (commandName === 'newacckick') {
    const val = interaction.options.getString('toggle') === 'on';
    config.newAccountKick = val;
    return interaction.reply({ embeds: [new EmbedBuilder()
      .setColor(0x1a1a2e)
      .setDescription(val
        ? '```diff\n-  new account auto-kick ENABLED\n-  accounts under 3 days old will be kicked\n```'
        : '```diff\n+  new account auto-kick DISABLED\n+  new accounts (like TikTok followers) can join safely\n```')
      .setFooter({ text: 'guardbot  ·  new account kick' }).setTimestamp()] });
  }

  // /antispam
  if (commandName === 'antispam') {
    const val = interaction.options.getString('toggle') === 'on';
    antiSpamEnabled.set(guild.id, val);
    return interaction.reply({ embeds: [new EmbedBuilder()
      .setColor(0x1a1a2e)
      .setDescription(`\`\`\`diff\n${val ? '+' : '-'}  anti-spam is now ${val ? 'enabled' : 'disabled'}\n\`\`\``)
      .setFooter({ text: 'guardbot  ·  anti-spam' }).setTimestamp()] });
  }

  // /antinuke
  if (commandName === 'antinuke') {
    const val = interaction.options.getString('toggle') === 'on';
    antiNukeEnabled.set(guild.id, val);
    return interaction.reply({ embeds: [new EmbedBuilder()
      .setColor(0x1a1a2e)
      .setDescription(`\`\`\`diff\n${val ? '+' : '-'}  anti-nuke is now ${val ? 'enabled' : 'disabled'}\n\`\`\``)
      .setFooter({ text: 'guardbot  ·  anti-nuke' }).setTimestamp()] });
  }

  // /antiraid
  if (commandName === 'antiraid') {
    const val = interaction.options.getString('toggle') === 'on';
    antiRaidEnabled.set(guild.id, val);
    return interaction.reply({ embeds: [new EmbedBuilder()
      .setColor(0x1a1a2e)
      .setDescription(`\`\`\`diff\n${val ? '+' : '-'}  anti-raid is now ${val ? 'enabled' : 'disabled'}\n\`\`\``)
      .setFooter({ text: 'guardbot  ·  anti-raid' }).setTimestamp()] });
  }

  // /raidmode
  if (commandName === 'raidmode') {
    const val = interaction.options.getString('toggle') === 'on';
    raidMode.set(guild.id, val);
    return interaction.reply({ embeds: [new EmbedBuilder()
      .setColor(val ? 0xff0000 : 0x1a1a2e)
      .setDescription(val
        ? '```diff\n-  ⚠  raid mode activated\n-  all new joins will be kicked\n```'
        : '```diff\n+  raid mode deactivated\n+  server is back to normal\n```')
      .setFooter({ text: 'guardbot  ·  raid mode' }).setTimestamp()] });
  }

  // /whitelist
  if (commandName === 'whitelist') {
    const user = interaction.options.getUser('user');
    if (!whitelist.has(guild.id)) whitelist.set(guild.id, new Set());
    whitelist.get(guild.id).add(user.id);
    return interaction.reply({ embeds: [new EmbedBuilder()
      .setColor(0x1a1a2e)
      .setDescription(`\`\`\`diff\n+  ${user.tag} added to whitelist\n+  exempt from all anti-nuke detection\n\`\`\``)
      .setFooter({ text: 'guardbot  ·  whitelist' }).setTimestamp()] });
  }

  // /unwhitelist
  if (commandName === 'unwhitelist') {
    const user = interaction.options.getUser('user');
    whitelist.get(guild.id)?.delete(user.id);
    return interaction.reply({ embeds: [new EmbedBuilder()
      .setColor(0x1a1a2e)
      .setDescription(`\`\`\`diff\n-  ${user.tag} removed from whitelist\n\`\`\``)
      .setFooter({ text: 'guardbot  ·  whitelist' }).setTimestamp()] });
  }
});

// ─── START ───────────────────────────────────────────────────────────────────
client.login(config.token);

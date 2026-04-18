require('dotenv').config();
const { Client, GatewayIntentBits, Partials, Collection, EmbedBuilder, PermissionFlagsBits, ActivityType } = require('discord.js');
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
  token: process.env.DISCORD_TOKEN,
  prefix: '!',

  // Anti-Raid thresholds
  joinRateLimit: 10,           // max joins per window
  joinRateWindow: 10000,       // window in ms (10 seconds)
  newAccountAge: 7,            // days — flag accounts newer than this

  // Anti-Nuke thresholds (per minute)
  maxChannelDeletes: 3,
  maxRoleDeletes: 3,
  maxBans: 5,
  maxKicks: 5,
  maxWebhookCreates: 3,

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

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function getLogChannel(guild) {
  return guild.channels.cache.find(
    c => c.name === config.logChannelName && c.isTextBased()
  );
}

async function sendLog(guild, embed) {
  const ch = getLogChannel(guild);
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
      .setTitle('🔒 Anti-Nuke Triggered')
      .setColor(0xff0000)
      .addFields(
        { name: 'User', value: `<@${userId}> (${userId})`, inline: true },
        { name: 'Reason', value: reason, inline: true },
        { name: 'Action', value: 'Banned', inline: true }
      )
      .setTimestamp();
    await sendLog(guild, embed);
  } catch (e) {
    console.error('punishNuker error:', e);
  }
}

// ─── ANTI-RAID: Join tracking ────────────────────────────────────────────────
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
      .setTitle('🚨 RAID MODE ACTIVATED')
      .setColor(0xff3300)
      .setDescription(`**${recent.length} joins** detected in the last ${config.joinRateWindow / 1000}s.\nNew joins will be kicked automatically.`)
      .setTimestamp();
    await sendLog(member.guild, embed);
  }

  if (raidMode.get(guildId)) {
    await member.kick('[Anti-Raid] Raid mode active').catch(() => {});

    const embed = new EmbedBuilder()
      .setTitle('🛡️ Anti-Raid: Member Kicked')
      .setColor(0xff6600)
      .addFields(
        { name: 'User', value: `${member.user.tag} (${member.id})`, inline: true },
        { name: 'Account Age', value: `${accountAge.toFixed(1)} days`, inline: true },
        { name: 'New Account?', value: isNewAccount ? '⚠️ Yes' : 'No', inline: true }
      )
      .setTimestamp();
    await sendLog(member.guild, embed);
    return;
  }

  // Warn about new accounts even outside raid mode
  if (isNewAccount) {
    const embed = new EmbedBuilder()
      .setTitle('⚠️ New Account Joined')
      .setColor(0xffaa00)
      .addFields(
        { name: 'User', value: `${member.user.tag} (${member.id})`, inline: true },
        { name: 'Account Age', value: `${accountAge.toFixed(1)} days`, inline: true }
      )
      .setTimestamp();
    await sendLog(member.guild, embed);
  }
});

// ─── ANTI-NUKE: Channel deletes ──────────────────────────────────────────────
client.on('channelDelete', async channel => {
  if (!channel.guild) return;
  if (!isAntiNukeEnabled(channel.guild.id)) return;

  const entry = await channel.guild.fetchAuditLogs({ type: 12, limit: 1 }).catch(() => null);
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

  const entry = await role.guild.fetchAuditLogs({ type: 32, limit: 1 }).catch(() => null);
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

  const entry = await ban.guild.fetchAuditLogs({ type: 22, limit: 1 }).catch(() => null);
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

  const entry = await member.guild.fetchAuditLogs({ type: 20, limit: 1 }).catch(() => null);
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

  const entry = await channel.guild.fetchAuditLogs({ type: 101, limit: 1 }).catch(() => null);
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

// ─── READY ───────────────────────────────────────────────────────────────────
client.once('clientReady', async () => {
  console.log(`✅ Logged in as ${client.user.tag}`);

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
      .setTitle('🛡️ GuardBot — Command List')
      .setColor(0x5865f2)
      .setDescription('A powerful anti-raid & anti-nuke bot to keep your server safe.')
      .addFields(
        { name: '🔒 Anti-Nuke', value: '`/antinuke on|off` — Toggle nuke protection\n`/whitelist @user` — Whitelist a trusted user\n`/unwhitelist @user` — Remove whitelist', inline: false },
        { name: '🛡️ Anti-Raid', value: '`/antiraid on|off` — Toggle raid protection\n`/raidmode on|off` — Manually enable raid lockdown', inline: false },
        { name: '📊 Info', value: '`/status` — View protection status\n`/bio` — About the bot\n`/help` — This menu', inline: false },
        { name: '⚙️ Thresholds (defaults)', value: `• Raid trigger: **${config.joinRateLimit} joins** in ${config.joinRateWindow / 1000}s\n• Nuke trigger: **${config.maxBans} bans**, **${config.maxChannelDeletes} ch-deletes**, **${config.maxRoleDeletes} role-deletes** per minute`, inline: false }
      )
      .setFooter({ text: 'All admin commands require Administrator permission' })
      .setTimestamp();
    return interaction.reply({ embeds: [embed] });
  }

  // /bio
  if (commandName === 'bio') {
    const embed = new EmbedBuilder()
      .setTitle('🤖 GuardBot — Bio')
      .setColor(0x57f287)
      .setThumbnail(client.user.displayAvatarURL())
      .setDescription('**GuardBot** is a 24/7 security bot built to protect Discord servers from raids and nukes.')
      .addFields(
        { name: '🛡️ Anti-Raid', value: 'Detects mass join floods and new accounts. Auto-kicks during raids.', inline: false },
        { name: '🔒 Anti-Nuke', value: 'Monitors mass bans, kicks, channel/role deletions, and webhook abuse. Bans the attacker instantly.', inline: false },
        { name: '✅ Whitelist System', value: 'Trusted admins can be whitelisted to bypass nuke detection.', inline: false },
        { name: '🔄 24/7 Online', value: 'Designed to run continuously with rotating status messages.', inline: false },
        { name: '⚡ Slash Commands', value: 'All commands available via `/` — no prefix needed.', inline: false },
        { name: '📅 Version', value: '1.0.0', inline: true },
        { name: '🏗️ Built With', value: 'discord.js v14', inline: true },
      )
      .setTimestamp();
    return interaction.reply({ embeds: [embed] });
  }

  // /status
  if (commandName === 'status') {
    const raidEnabled = isAntiRaidEnabled(guild.id);
    const nukeEnabled = isAntiNukeEnabled(guild.id);
    const inRaid = raidMode.get(guild.id) || false;
    const wl = whitelist.get(guild.id) || new Set();

    const embed = new EmbedBuilder()
      .setTitle('📊 Protection Status')
      .setColor(inRaid ? 0xff3300 : 0x57f287)
      .addFields(
        { name: '🛡️ Anti-Raid', value: raidEnabled ? '✅ Enabled' : '❌ Disabled', inline: true },
        { name: '🔒 Anti-Nuke', value: nukeEnabled ? '✅ Enabled' : '❌ Disabled', inline: true },
        { name: '🚨 Raid Mode', value: inRaid ? '🔴 ACTIVE' : '🟢 Inactive', inline: true },
        { name: '✅ Whitelisted Users', value: wl.size > 0 ? [...wl].map(id => `<@${id}>`).join(', ') : 'None', inline: false },
      )
      .setTimestamp();
    return interaction.reply({ embeds: [embed] });
  }

  // Admin-only commands below
  if (!isAdmin) {
    return interaction.reply({ content: '❌ You need **Administrator** permission to use this command.', ephemeral: true });
  }

  // /antinuke
  if (commandName === 'antinuke') {
    const val = interaction.options.getString('toggle') === 'on';
    antiNukeEnabled.set(guild.id, val);
    return interaction.reply({
      embeds: [new EmbedBuilder()
        .setColor(val ? 0x57f287 : 0xff4444)
        .setDescription(`🔒 Anti-Nuke is now **${val ? 'ENABLED' : 'DISABLED'}**`)
        .setTimestamp()]
    });
  }

  // /antiraid
  if (commandName === 'antiraid') {
    const val = interaction.options.getString('toggle') === 'on';
    antiRaidEnabled.set(guild.id, val);
    return interaction.reply({
      embeds: [new EmbedBuilder()
        .setColor(val ? 0x57f287 : 0xff4444)
        .setDescription(`🛡️ Anti-Raid is now **${val ? 'ENABLED' : 'DISABLED'}**`)
        .setTimestamp()]
    });
  }

  // /raidmode
  if (commandName === 'raidmode') {
    const val = interaction.options.getString('toggle') === 'on';
    raidMode.set(guild.id, val);
    return interaction.reply({
      embeds: [new EmbedBuilder()
        .setColor(val ? 0xff3300 : 0x57f287)
        .setDescription(`🚨 Raid Mode is now **${val ? '🔴 ACTIVE — New joins will be kicked!' : '🟢 Deactivated'}**`)
        .setTimestamp()]
    });
  }

  // /whitelist
  if (commandName === 'whitelist') {
    const user = interaction.options.getUser('user');
    if (!whitelist.has(guild.id)) whitelist.set(guild.id, new Set());
    whitelist.get(guild.id).add(user.id);
    return interaction.reply({
      embeds: [new EmbedBuilder()
        .setColor(0x57f287)
        .setDescription(`✅ <@${user.id}> has been **whitelisted** and is exempt from anti-nuke actions.`)
        .setTimestamp()]
    });
  }

  // /unwhitelist
  if (commandName === 'unwhitelist') {
    const user = interaction.options.getUser('user');
    whitelist.get(guild.id)?.delete(user.id);
    return interaction.reply({
      embeds: [new EmbedBuilder()
        .setColor(0xff4444)
        .setDescription(`❌ <@${user.id}> has been **removed** from the whitelist.`)
        .setTimestamp()]
    });
  }
});

// ─── START ───────────────────────────────────────────────────────────────────
client.login(config.token);

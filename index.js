const { Client, GatewayIntentBits, Partials, Collection, EmbedBuilder, PermissionFlagsBits, ActivityType, AuditLogEvent, ActionRowBuilder, ButtonBuilder, ButtonStyle, ChannelType } = require('discord.js');
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
    GatewayIntentBits.GuildModeration,
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
  newAccountAge: 7,            // days — flag accounts newer than this (increased from 3)
  newAccountKick: false,       // auto-kick new accounts? OFF by default

  // Anti-Nuke thresholds (per minute) - MORE STRICT
  maxChannelDeletes: 2,        // reduced from 3
  maxChannelCreates: 5,        // NEW: detect channel spam creation
  maxRoleDeletes: 2,           // reduced from 3
  maxRoleCreates: 5,           // NEW: detect role spam creation
  maxBans: 3,                  // reduced from 5
  maxKicks: 4,                 // reduced from 5
  maxWebhookCreates: 2,        // reduced from 3
  maxPermissionChanges: 5,     // NEW: detect permission abuse

  // Anti-Spam thresholds - MORE AGGRESSIVE
  maxMessagesPerWindow: 5,       
  spamWindow: 5000,              
  maxInviteSpam: 1,              // reduced from 2 - ZERO TOLERANCE
  maxMentionsPerMessage: 5,      // NEW: max mentions per message
  maxEmojisPerMessage: 15,       // NEW: max emojis per message
  maxCapsPercent: 70,            // NEW: max caps percentage
  minCapsLength: 10,             // NEW: min length to check caps
  maxLinksPerMessage: 3,         // NEW: max links per message
  spamMuteDuration: 30 * 60,     // increased to 30 mins (from 10)

  // Threat Level thresholds
  warningsBeforeMute: 2,
  mutesBeforeKick: 2,
  kicksBeforeBan: 2,

  // Auto-Slowmode
  autoSlowmodeThreshold: 10,     // messages per 5 seconds to trigger
  autoSlowmodeDuration: 10,      // slowmode seconds

  // Quarantine
  quarantineRoleName: 'Quarantine',

  // Log channel name
  logChannelName: 'mod-logs',

  // Bot status messages
  statuses: [
    { name: '🛡️ PROTECTING SERVER', type: ActivityType.Watching },
    { name: '⚡ THREAT DETECTED = INSTANT BAN', type: ActivityType.Playing },
    { name: '🔒 ZERO TOLERANCE MODE', type: ActivityType.Playing },
    { name: '👁️ WATCHING EVERYTHING', type: ActivityType.Watching },
    { name: '/help for commands', type: ActivityType.Listening },
    { name: '🚨 PANIC BUTTON READY', type: ActivityType.Playing },
  ],

  // Suspicious link patterns (phishing, scams)
  suspiciousPatterns: [
    /discord\.gift/i,
    /discordnitro/i,
    /free.*nitro/i,
    /steamcommunity\.[^com]/i,
    /steampowered\.[^com]/i,
    /bit\.ly/i,
    /tinyurl/i,
    /grabify/i,
    /iplogger/i,
    /pornhub/i,
    /xvideos/i,
    /\.(ru|cn|tk|ml|ga|cf|gq)\/\S+/i,
  ],

  // Banned words (auto-delete + warn)
  bannedWords: [
    // Add your banned words here
  ],
};

// ─── STATE ───────────────────────────────────────────────────────────────────
const joinLog = new Map();           // guildId → [timestamps]
const actionLog = new Map();         // guildId → { type → [timestamps] }
const raidMode = new Map();          // guildId → boolean
const whitelist = new Map();         // guildId → Set<userId>
const antiNukeEnabled = new Map();   // guildId → boolean
const antiRaidEnabled = new Map();   // guildId → boolean
const spamTracker = new Map();       // odding → { msgs: [], invites: [], mentions: [], etc }
const mutedUsers = new Map();        // odding → timeout
const antiSpamEnabled = new Map();   // guildId → boolean
const lockdownMode = new Map();      // guildId → boolean
const verificationEnabled = new Map(); // guildId → boolean
const threatLevel = new Map();       // odding → { warnings: 0, mutes: 0, kicks: 0 }
const messageLog = new Map();        // channelId → [timestamps] for auto-slowmode
const quarantinedUsers = new Map();  // odding → { guildId, timestamp }
const antiLinkEnabled = new Map();   // guildId → boolean (default ON)
const antiMentionEnabled = new Map(); // guildId → boolean (default ON)
const dmWarningsEnabled = new Map(); // guildId → boolean (default ON)
const maintenanceMode = new Map();   // guildId → { enabled: boolean, expiry: timestamp }
const trustedAdmins = new Map();     // guildId → Set<userId> - admins na pwede mag-ayos ng server
const trustedBots = new Map();       // guildId → Set<botId> - trusted bots (music, etc)

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

function isWhitelisted(guild, odding) {
  return whitelist.get(guild.id)?.has(odding) || false;
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
  return antiNukeEnabled.get(guildId) !== false;
}

function isAntiRaidEnabled(guildId) {
  return antiRaidEnabled.get(guildId) !== false;
}

function isAntiSpamEnabled(guildId) {
  return antiSpamEnabled.get(guildId) !== false;
}

function isAntiLinkEnabled(guildId) {
  return antiLinkEnabled.get(guildId) !== false;
}

function isAntiMentionEnabled(guildId) {
  return antiMentionEnabled.get(guildId) !== false;
}

function isDmWarningsEnabled(guildId) {
  return dmWarningsEnabled.get(guildId) !== false;
}

// ─── MAINTENANCE MODE & TRUSTED USERS ────────────────────────────────────────
function isMaintenanceMode(guildId) {
  const maint = maintenanceMode.get(guildId);
  if (!maint || !maint.enabled) return false;
  // Check if expired
  if (maint.expiry && Date.now() > maint.expiry) {
    maintenanceMode.set(guildId, { enabled: false, expiry: null });
    return false;
  }
  return true;
}

function isTrustedAdmin(guildId, userId) {
  return trustedAdmins.get(guildId)?.has(userId) || false;
}

function isTrustedBot(guildId, botId) {
  return trustedBots.get(guildId)?.has(botId) || false;
}

function shouldSkipAntiNuke(guild, executorId, executor) {
  // Always skip for server owner
  if (executorId === guild.ownerId) return true;
  
  // Skip if maintenance mode is on
  if (isMaintenanceMode(guild.id)) return true;
  
  // Skip if user is whitelisted
  if (isWhitelisted(guild, executorId)) return true;
  
  // Skip if trusted admin (human)
  if (!executor?.bot && isTrustedAdmin(guild.id, executorId)) return true;
  
  // Skip if trusted bot
  if (executor?.bot && isTrustedBot(guild.id, executorId)) return true;
  
  return false;
}

// ─── THREAT LEVEL SYSTEM ─────────────────────────────────────────────────────
function getThreatLevel(odding) {
  if (!threatLevel.has(odding)) {
    threatLevel.set(odding, { warnings: 0, mutes: 0, kicks: 0, lastAction: Date.now() });
  }
  return threatLevel.get(odding);
}

function incrementThreat(odding, type) {
  const threat = getThreatLevel(odding);
  threat[type]++;
  threat.lastAction = Date.now();
  return threat;
}

function getThreatScore(odding) {
  const threat = getThreatLevel(odding);
  return threat.warnings + (threat.mutes * 3) + (threat.kicks * 5);
}

// ─── DM WARNING SYSTEM ───────────────────────────────────────────────────────
async function sendDMWarning(user, guild, reason, action) {
  if (!isDmWarningsEnabled(guild.id)) return;
  
  const embed = new EmbedBuilder()
    .setColor(action === 'ban' ? 0xff0000 : action === 'kick' ? 0xff6600 : 0xffcc00)
    .setAuthor({ name: `⚠️ Warning from ${guild.name}` })
    .setDescription(`You have received a **${action.toUpperCase()}** from **${guild.name}**`)
    .addFields(
      { name: 'Reason', value: reason },
      { name: 'Threat Score', value: `${getThreatScore(user.id)}`, inline: true },
    )
    .setFooter({ text: 'GuardBot Security System' })
    .setTimestamp();

  try {
    await user.send({ embeds: [embed] });
  } catch (e) {
    // User has DMs disabled
  }
}

// ─── QUARANTINE SYSTEM ───────────────────────────────────────────────────────
async function ensureQuarantineRole(guild) {
  let role = guild.roles.cache.find(r => r.name === config.quarantineRoleName);
  
  if (!role) {
    role = await guild.roles.create({
      name: config.quarantineRoleName,
      color: 0x808080,
      permissions: [],
      reason: 'GuardBot: Auto-created quarantine role',
    }).catch(() => null);

    if (role) {
      // Deny all permissions in all channels
      for (const channel of guild.channels.cache.values()) {
        await channel.permissionOverwrites.edit(role, {
          ViewChannel: false,
          SendMessages: false,
          AddReactions: false,
          Speak: false,
        }).catch(() => {});
      }
    }
  }
  
  return role;
}

async function quarantineUser(guild, member, reason) {
  const role = await ensureQuarantineRole(guild);
  if (!role) return false;

  try {
    await member.roles.add(role, `[Quarantine] ${reason}`);
    quarantinedUsers.set(member.id, { guildId: guild.id, timestamp: Date.now() });

    const embed = new EmbedBuilder()
      .setColor(0x808080)
      .setAuthor({ name: '🔒 USER QUARANTINED' })
      .setDescription('```diff\n- User has been isolated from the server\n```')
      .addFields(
        { name: 'User', value: `<@${member.id}> · \`${member.id}\``, inline: true },
        { name: 'Reason', value: reason, inline: true },
        { name: 'Action', value: 'Use `/unquarantine` to release', inline: false },
      )
      .setFooter({ text: 'guardbot · quarantine system' })
      .setTimestamp();
    await sendLog(guild, embed);

    await sendDMWarning(member.user, guild, reason, 'quarantine');
    return true;
  } catch (e) {
    console.error('quarantineUser error:', e);
    return false;
  }
}

// ─── LOCKDOWN SYSTEM ─────────────────────────────────────────────────────────
async function toggleLockdown(guild, enable) {
  lockdownMode.set(guild.id, enable);
  
  const everyone = guild.roles.everyone;
  
  for (const channel of guild.channels.cache.values()) {
    if (channel.type === ChannelType.GuildText || channel.type === ChannelType.GuildVoice) {
      try {
        await channel.permissionOverwrites.edit(everyone, {
          SendMessages: enable ? false : null,
          Speak: enable ? false : null,
          AddReactions: enable ? false : null,
        });
      } catch (e) {}
    }
  }

  const embed = new EmbedBuilder()
    .setColor(enable ? 0xff0000 : 0x00ff00)
    .setAuthor({ name: enable ? '🚨 SERVER LOCKDOWN ACTIVATED' : '✅ LOCKDOWN LIFTED' })
    .setDescription(enable 
      ? '```diff\n- ALL CHANNELS LOCKED\n- NO ONE CAN SEND MESSAGES\n- EMERGENCY MODE ACTIVE\n```'
      : '```diff\n+ Server restored to normal\n+ All channels unlocked\n```')
    .setFooter({ text: 'guardbot · lockdown system' })
    .setTimestamp();
  await sendLog(guild, embed);
}

// ─── PUNISH NUKER (ENHANCED) ─────────────────────────────────────────────────
async function punishNuker(guild, odding, reason) {
  if (isWhitelisted(guild, odding)) return;
  
  try {
    const member = await guild.members.fetch(odding).catch(() => null);
    if (!member) return;
    
    // Skip server owner
    if (member.id === guild.ownerId) return;
    
    // Check if admin - quarantine instead of ban
    if (member.permissions.has(PermissionFlagsBits.Administrator)) {
      // Remove all roles first (strip permissions)
      const rolesToRemove = member.roles.cache.filter(r => r.id !== guild.id);
      await member.roles.remove(rolesToRemove, `[Anti-Nuke] ${reason}`).catch(() => {});
      await quarantineUser(guild, member, reason);
      
      const embed = new EmbedBuilder()
        .setColor(0xff0000)
        .setAuthor({ name: '⚠️ ADMIN COMPROMISED - PERMISSIONS STRIPPED' })
        .setDescription('```diff\n- Admin attempted nuke\n- All roles removed\n- User quarantined\n```')
        .addFields(
          { name: 'User', value: `<@${odding}> · \`${odding}\``, inline: true },
          { name: 'Reason', value: reason, inline: true },
        )
        .setFooter({ text: 'guardbot · anti-nuke' })
        .setTimestamp();
      await sendLog(guild, embed);
      return;
    }

    // Non-admin: instant ban
    await sendDMWarning(member.user, guild, reason, 'ban');
    await member.ban({ reason: `[Anti-Nuke] ${reason}`, deleteMessageSeconds: 604800 }); // Delete 7 days of messages

    const embed = new EmbedBuilder()
      .setColor(0xff0000)
      .setAuthor({ name: '⬡ ANTI-NUKE TRIGGERED' })
      .setDescription('```diff\n- NUKE ATTEMPT DETECTED & NEUTRALIZED\n```')
      .addFields(
        { name: 'User', value: `<@${odding}> · \`${odding}\``, inline: true },
        { name: 'Reason', value: reason, inline: true },
        { name: 'Action', value: '```diff\n- BANNED + 7 DAY MSG PURGE\n```', inline: true },
      )
      .setFooter({ text: 'guardbot · anti-nuke' })
      .setTimestamp();
    await sendLog(guild, embed);
  } catch (e) {
    console.error('punishNuker error:', e);
  }
}

// ─── INSTANT BAN BOT (ZERO TOLERANCE) ────────────────────────────────────────
async function instantBanBot(guild, botId, reason) {
  if (isWhitelisted(guild, botId)) return;
  
  try {
    const botMember = await guild.members.fetch(botId).catch(() => null);
    
    // Even if we can't fetch the member, try to ban by ID
    await guild.members.ban(botId, { 
      reason: `[ANTI-NUKE BOT PROTECTION] ${reason}`, 
      deleteMessageSeconds: 604800 // Delete 7 days of messages
    });

    const embed = new EmbedBuilder()
      .setColor(0xff0000)
      .setAuthor({ name: '🤖 MALICIOUS BOT BANNED INSTANTLY' })
      .setDescription('```diff\n- BOT NUKE ATTEMPT DETECTED\n- ZERO TOLERANCE POLICY ACTIVATED\n- BOT TERMINATED IMMEDIATELY\n```')
      .addFields(
        { name: 'Bot ID', value: `\`${botId}\``, inline: true },
        { name: 'Bot Name', value: botMember ? `${botMember.user.tag}` : 'Unknown', inline: true },
        { name: 'Reason', value: reason, inline: false },
        { name: 'Action', value: '```diff\n- INSTANT BAN + 7 DAY MSG PURGE\n```', inline: false },
      )
      .setFooter({ text: 'guardbot · anti-bot-nuke · zero tolerance' })
      .setTimestamp();
    await sendLog(guild, embed);

    // Also try to revoke the bot's OAuth2 authorization (kick from integrations)
    // This requires fetching and removing integrations
    try {
      const integrations = await guild.fetchIntegrations();
      for (const [id, integration] of integrations) {
        if (integration.application?.id === botId || integration.account?.id === botId) {
          await integration.delete(`[Anti-Nuke] Removing malicious bot integration`);
        }
      }
    } catch (e) {
      // Integration removal failed, but ban succeeded
    }

  } catch (e) {
    console.error('instantBanBot error:', e);
    
    // If ban failed, log the attempt
    const embed = new EmbedBuilder()
      .setColor(0xff6600)
      .setAuthor({ name: '⚠️ FAILED TO BAN MALICIOUS BOT' })
      .setDescription('```diff\n- Bot nuke detected but ban failed\n- Manual intervention required\n```')
      .addFields(
        { name: 'Bot ID', value: `\`${botId}\``, inline: true },
        { name: 'Reason', value: reason, inline: false },
        { name: 'Error', value: `${e.message}`, inline: false },
      )
      .setFooter({ text: 'guardbot · anti-bot-nuke' })
      .setTimestamp();
    await sendLog(guild, embed);
  }
}

// ─── ENHANCED MUTE SYSTEM ────────────────────────────────────────────────────
async function muteUser(guild, member, reason, duration = config.spamMuteDuration) {
  const threat = incrementThreat(member.id, 'mutes');
  
  // Check if should escalate to kick/ban
  if (threat.mutes >= config.mutesBeforeKick) {
    if (threat.kicks >= config.kicksBeforeBan) {
      // BAN
      await sendDMWarning(member.user, guild, `${reason} (Repeated violations)`, 'ban');
      await member.ban({ reason: `[Anti-Spam] Repeated violations: ${reason}`, deleteMessageSeconds: 86400 }).catch(() => {});
      
      const embed = new EmbedBuilder()
        .setColor(0xff0000)
        .setAuthor({ name: '🔨 USER BANNED - REPEATED VIOLATIONS' })
        .addFields(
          { name: 'User', value: `<@${member.id}> · \`${member.id}\``, inline: true },
          { name: 'Reason', value: reason, inline: true },
          { name: 'Threat Score', value: `${getThreatScore(member.id)}`, inline: true },
        )
        .setFooter({ text: 'guardbot · threat escalation' })
        .setTimestamp();
      await sendLog(guild, embed);
      return;
    }
    
    // KICK
    incrementThreat(member.id, 'kicks');
    await sendDMWarning(member.user, guild, `${reason} (Multiple mutes)`, 'kick');
    await member.kick(`[Anti-Spam] Multiple mutes: ${reason}`).catch(() => {});
    
    const embed = new EmbedBuilder()
      .setColor(0xff6600)
      .setAuthor({ name: '👢 USER KICKED - MULTIPLE MUTES' })
      .addFields(
        { name: 'User', value: `<@${member.id}> · \`${member.id}\``, inline: true },
        { name: 'Reason', value: reason, inline: true },
        { name: 'Mute Count', value: `${threat.mutes}`, inline: true },
      )
      .setFooter({ text: 'guardbot · threat escalation' })
      .setTimestamp();
    await sendLog(guild, embed);
    return;
  }

  try {
    const until = new Date(Date.now() + duration * 1000);
    await member.timeout(duration * 1000, `[Anti-Spam] ${reason}`);
    await sendDMWarning(member.user, guild, reason, 'mute');

    const embed = new EmbedBuilder()
      .setColor(0xff6600)
      .setAuthor({ name: '🔇 USER MUTED' })
      .addFields(
        { name: 'User', value: `<@${member.id}> · \`${member.id}\``, inline: true },
        { name: 'Reason', value: reason, inline: true },
        { name: 'Duration', value: `${duration / 60} minutes`, inline: true },
        { name: 'Threat Score', value: `${getThreatScore(member.id)}`, inline: true },
        { name: 'Mute #', value: `${threat.mutes}/${config.mutesBeforeKick} before kick`, inline: true },
      )
      .setFooter({ text: 'guardbot · anti-spam' })
      .setTimestamp();
    await sendLog(guild, embed);
  } catch (e) {
    console.error('muteUser error:', e);
  }
}

// ─── AUTO-SLOWMODE ───────────────────────────────────────────────────────────
async function checkAutoSlowmode(channel) {
  const channelId = channel.id;
  const now = Date.now();
  
  if (!messageLog.has(channelId)) messageLog.set(channelId, []);
  const msgs = messageLog.get(channelId);
  msgs.push(now);
  
  // Clean old (keep last 5 seconds)
  const recent = msgs.filter(t => now - t < 5000);
  messageLog.set(channelId, recent);
  
  if (recent.length >= config.autoSlowmodeThreshold && channel.rateLimitPerUser < config.autoSlowmodeDuration) {
    await channel.setRateLimitPerUser(config.autoSlowmodeDuration, '[GuardBot] Auto-slowmode triggered').catch(() => {});
    
    const embed = new EmbedBuilder()
      .setColor(0xffcc00)
      .setAuthor({ name: '🐌 AUTO-SLOWMODE ACTIVATED' })
      .addFields(
        { name: 'Channel', value: `<#${channel.id}>`, inline: true },
        { name: 'Duration', value: `${config.autoSlowmodeDuration}s`, inline: true },
        { name: 'Trigger', value: `${recent.length} msgs/5s`, inline: true },
      )
      .setFooter({ text: 'guardbot · auto-slowmode' })
      .setTimestamp();
    await sendLog(channel.guild, embed);
    
    // Auto-disable after 2 minutes
    setTimeout(async () => {
      if (channel.rateLimitPerUser === config.autoSlowmodeDuration) {
        await channel.setRateLimitPerUser(0, '[GuardBot] Auto-slowmode expired').catch(() => {});
      }
    }, 120000);
  }
}

// ─── REGEX PATTERNS ──────────────────────────────────────────────────────────
const INVITE_REGEX = /(discord\.gg|discord\.com\/invite|discordapp\.com\/invite|dsc\.gg)\/[a-zA-Z0-9]+/gi;
const URL_REGEX = /https?:\/\/[^\s]+/gi;
const MENTION_REGEX = /<@[!&]?\d+>|@everyone|@here/g;
const EMOJI_REGEX = /<a?:\w+:\d+>|[\u{1F300}-\u{1F9FF}]|[\u{2600}-\u{26FF}]|[\u{2700}-\u{27BF}]/gu;

// ─── ANTI-SPAM MESSAGE HANDLER ───────────────────────────────────────────────
client.on('messageCreate', async message => {
  if (!message.guild) return;
  if (message.author.bot) return;
  if (isWhitelisted(message.guild, message.author.id)) return;
  
  const member = message.member;
  if (!member) return;
  
  // Skip admins and moderators
  if (member.permissions.has(PermissionFlagsBits.ManageMessages)) return;
  
  // Check lockdown
  if (lockdownMode.get(message.guild.id)) {
    await message.delete().catch(() => {});
    return;
  }

  const content = message.content;
  const odding = message.author.id;
  const guildId = message.guild.id;
  const now = Date.now();

  // Auto-slowmode check
  await checkAutoSlowmode(message.channel);

  // Init tracker
  if (!spamTracker.has(odding)) {
    spamTracker.set(odding, { msgs: [], invites: [], mentions: [], links: [], content: [] });
  }
  const tracker = spamTracker.get(odding);
  
  // Clean old entries
  Object.keys(tracker).forEach(key => {
    if (Array.isArray(tracker[key])) {
      tracker[key] = tracker[key].filter(t => typeof t === 'number' ? now - t < config.spamWindow : now - t.time < config.spamWindow);
    }
  });

  // ── BANNED WORDS CHECK ─────────────────────────────────────────────────────
  if (config.bannedWords.length > 0) {
    const lowerContent = content.toLowerCase();
    const hasBannedWord = config.bannedWords.some(word => lowerContent.includes(word.toLowerCase()));
    if (hasBannedWord) {
      await message.delete().catch(() => {});
      incrementThreat(odding, 'warnings');
      
      const embed = new EmbedBuilder()
        .setColor(0xff0000)
        .setAuthor({ name: '🚫 BANNED WORD DETECTED' })
        .addFields(
          { name: 'User', value: `<@${odding}>`, inline: true },
          { name: 'Channel', value: `<#${message.channel.id}>`, inline: true },
        )
        .setFooter({ text: 'guardbot · content filter' })
        .setTimestamp();
      await sendLog(message.guild, embed);
      return;
    }
  }

  // ── SUSPICIOUS LINKS CHECK ─────────────────────────────────────────────────
  if (isAntiLinkEnabled(guildId)) {
    const isSuspicious = config.suspiciousPatterns.some(pattern => pattern.test(content));
    if (isSuspicious) {
      await message.delete().catch(() => {});
      await muteUser(message.guild, member, 'Suspicious/phishing link detected', config.spamMuteDuration * 2);
      
      const embed = new EmbedBuilder()
        .setColor(0xff0000)
        .setAuthor({ name: '🎣 PHISHING LINK DETECTED' })
        .setDescription('```diff\n- Potential scam/phishing link blocked\n```')
        .addFields(
          { name: 'User', value: `<@${odding}>`, inline: true },
          { name: 'Channel', value: `<#${message.channel.id}>`, inline: true },
          { name: 'Action', value: 'Muted 1 hour', inline: true },
        )
        .setFooter({ text: 'guardbot · anti-phishing' })
        .setTimestamp();
      await sendLog(message.guild, embed);
      return;
    }
  }

  // ── DISCORD INVITE LINKS ───────────────────────────────────────────────────
  if (isAntiSpamEnabled(guildId)) {
    const inviteMatches = content.match(INVITE_REGEX);
    if (inviteMatches) {
      tracker.invites.push(now);
      await message.delete().catch(() => {});

      if (tracker.invites.length >= config.maxInviteSpam) {
        await muteUser(message.guild, member, `Invite link spam (${tracker.invites.length} links)`);
        tracker.invites = [];
      } else {
        incrementThreat(odding, 'warnings');
        const warn = await message.channel.send({
          content: `<@${odding}> ⚠️ **NO ADVERTISING!** Discord invite links are NOT allowed.`
        }).catch(() => null);
        if (warn) setTimeout(() => warn.delete().catch(() => {}), 5000);
      }

      const embed = new EmbedBuilder()
        .setColor(0xff6600)
        .setAuthor({ name: '⬡ INVITE LINK BLOCKED' })
        .addFields(
          { name: 'User', value: `<@${odding}>`, inline: true },
          { name: 'Channel', value: `<#${message.channel.id}>`, inline: true },
          { name: 'Threat Score', value: `${getThreatScore(odding)}`, inline: true },
        )
        .setFooter({ text: 'guardbot · anti-spam' })
        .setTimestamp();
      await sendLog(message.guild, embed);
      return;
    }
  }

  // ── MASS MENTION CHECK ─────────────────────────────────────────────────────
  if (isAntiMentionEnabled(guildId)) {
    const mentions = content.match(MENTION_REGEX) || [];
    const hasEveryoneHere = content.includes('@everyone') || content.includes('@here');
    
    if (hasEveryoneHere && !member.permissions.has(PermissionFlagsBits.MentionEveryone)) {
      await message.delete().catch(() => {});
      await muteUser(message.guild, member, 'Attempted @everyone/@here mention', config.spamMuteDuration * 2);
      
      const embed = new EmbedBuilder()
        .setColor(0xff0000)
        .setAuthor({ name: '📢 MASS MENTION ATTEMPT BLOCKED' })
        .addFields(
          { name: 'User', value: `<@${odding}>`, inline: true },
          { name: 'Attempted', value: '@everyone/@here', inline: true },
        )
        .setFooter({ text: 'guardbot · anti-mention' })
        .setTimestamp();
      await sendLog(message.guild, embed);
      return;
    }

    if (mentions.length > config.maxMentionsPerMessage) {
      await message.delete().catch(() => {});
      tracker.mentions.push(now);
      
      if (tracker.mentions.length >= 2) {
        await muteUser(message.guild, member, `Mass mention spam (${mentions.length} mentions)`);
        tracker.mentions = [];
      } else {
        incrementThreat(odding, 'warnings');
      }

      const embed = new EmbedBuilder()
        .setColor(0xff6600)
        .setAuthor({ name: '📢 MASS MENTION BLOCKED' })
        .addFields(
          { name: 'User', value: `<@${odding}>`, inline: true },
          { name: 'Mentions', value: `${mentions.length}`, inline: true },
        )
        .setFooter({ text: 'guardbot · anti-mention' })
        .setTimestamp();
      await sendLog(message.guild, embed);
      return;
    }
  }

  // ── EMOJI SPAM CHECK ───────────────────────────────────────────────────────
  if (isAntiSpamEnabled(guildId)) {
    const emojis = content.match(EMOJI_REGEX) || [];
    if (emojis.length > config.maxEmojisPerMessage) {
      await message.delete().catch(() => {});
      incrementThreat(odding, 'warnings');
      
      const embed = new EmbedBuilder()
        .setColor(0xffcc00)
        .setAuthor({ name: '😀 EMOJI SPAM BLOCKED' })
        .addFields(
          { name: 'User', value: `<@${odding}>`, inline: true },
          { name: 'Emoji Count', value: `${emojis.length}`, inline: true },
        )
        .setFooter({ text: 'guardbot · anti-spam' })
        .setTimestamp();
      await sendLog(message.guild, embed);
      return;
    }
  }

  // ── CAPS SPAM CHECK ────────────────────────────────────────────────────────
  if (isAntiSpamEnabled(guildId) && content.length >= config.minCapsLength) {
    const letters = content.replace(/[^a-zA-Z]/g, '');
    if (letters.length > 0) {
      const capsCount = letters.replace(/[^A-Z]/g, '').length;
      const capsPercent = (capsCount / letters.length) * 100;
      
      if (capsPercent >= config.maxCapsPercent) {
        await message.delete().catch(() => {});
        incrementThreat(odding, 'warnings');
        
        const warn = await message.channel.send({
          content: `<@${odding}> ⚠️ Please don't use excessive CAPS.`
        }).catch(() => null);
        if (warn) setTimeout(() => warn.delete().catch(() => {}), 5000);
        return;
      }
    }
  }

  // ── LINK SPAM CHECK ────────────────────────────────────────────────────────
  if (isAntiLinkEnabled(guildId)) {
    const links = content.match(URL_REGEX) || [];
    if (links.length > config.maxLinksPerMessage) {
      await message.delete().catch(() => {});
      tracker.links.push(now);
      
      if (tracker.links.length >= 2) {
        await muteUser(message.guild, member, `Link spam (${links.length} links in message)`);
        tracker.links = [];
      } else {
        incrementThreat(odding, 'warnings');
      }
      return;
    }
  }

  // ── DUPLICATE MESSAGE SPAM ─────────────────────────────────────────────────
  if (isAntiSpamEnabled(guildId)) {
    tracker.content.push({ text: content, time: now });
    const recentDuplicates = tracker.content.filter(m => m.text === content);
    
    if (recentDuplicates.length >= 3) {
      await message.delete().catch(() => {});
      await muteUser(message.guild, member, 'Duplicate message spam');
      tracker.content = [];
      return;
    }

    // General message rate
    tracker.msgs.push(now);
    if (tracker.msgs.length >= config.maxMessagesPerWindow) {
      await message.delete().catch(() => {});
      await muteUser(message.guild, member, `Message flood (${tracker.msgs.length} msgs/${config.spamWindow/1000}s)`);
      tracker.msgs = [];
    }
  }
});

// ─── ANTI-RAID: Member Join ──────────────────────────────────────────────────
client.on('guildMemberAdd', async member => {
  if (!isAntiRaidEnabled(member.guild.id)) return;

  const guildId = member.guild.id;
  const now = Date.now();

  // Track joins
  if (!joinLog.has(guildId)) joinLog.set(guildId, []);
  const joins = joinLog.get(guildId);
  joins.push(now);
  const recent = joins.filter(t => now - t < config.joinRateWindow);
  joinLog.set(guildId, recent);

  const accountAge = (now - member.user.createdTimestamp) / 86400000;
  const isNewAccount = accountAge < config.newAccountAge;

  // Activate raid mode if threshold hit
  if (recent.length >= config.joinRateLimit) {
    raidMode.set(guildId, true);
    
    // Auto-lockdown on severe raid
    if (recent.length >= config.joinRateLimit * 2) {
      await toggleLockdown(member.guild, true);
    }

    const embed = new EmbedBuilder()
      .setColor(0xff0000)
      .setAuthor({ name: '🚨 RAID MODE ACTIVATED' })
      .setDescription(`\`\`\`diff\n- ${recent.length} JOINS IN ${config.joinRateWindow / 1000}s\n- ALL NEW JOINS WILL BE KICKED\n${recent.length >= config.joinRateLimit * 2 ? '- SERVER LOCKDOWN ENABLED\n' : ''}\`\`\``)
      .setFooter({ text: 'guardbot · anti-raid' })
      .setTimestamp();
    await sendLog(member.guild, embed);
  }

  if (raidMode.get(guildId)) {
    await sendDMWarning(member.user, member.guild, 'Server is under raid protection. Please try again later.', 'kick');
    await member.kick('[Anti-Raid] Raid mode active').catch(() => {});

    const embed = new EmbedBuilder()
      .setColor(0xff6600)
      .setAuthor({ name: '⬡ RAID KICK' })
      .addFields(
        { name: 'User', value: `${member.user.tag} · \`${member.id}\``, inline: true },
        { name: 'Account Age', value: `${accountAge.toFixed(1)} days`, inline: true },
        { name: 'New Account', value: isNewAccount ? '```diff\n- YES ⚠\n```' : '```diff\n+ no\n```', inline: true },
      )
      .setFooter({ text: 'guardbot · anti-raid' })
      .setTimestamp();
    await sendLog(member.guild, embed);
    return;
  }

  // New account handling
  if (isNewAccount) {
    if (config.newAccountKick && !isWhitelisted(member.guild, member.id)) {
      await sendDMWarning(member.user, member.guild, 'Your account is too new. Please try again in a few days.', 'kick');
      await member.kick('[Anti-Raid] New account — too young').catch(() => {});
      
      const embed = new EmbedBuilder()
        .setColor(0xff6600)
        .setAuthor({ name: '⬡ NEW ACCOUNT KICKED' })
        .addFields(
          { name: 'User', value: `${member.user.tag} · \`${member.id}\``, inline: true },
          { name: 'Account Age', value: `${accountAge.toFixed(1)} days`, inline: true },
        )
        .setFooter({ text: 'guardbot · anti-raid' })
        .setTimestamp();
      await sendLog(member.guild, embed);
      return;
    }

    // Just flag - don't kick
    const embed = new EmbedBuilder()
      .setColor(0xffcc00)
      .setAuthor({ name: '⚠️ NEW ACCOUNT JOINED' })
      .addFields(
        { name: 'User', value: `${member.user.tag} · \`${member.id}\``, inline: true },
        { name: 'Account Age', value: `${accountAge.toFixed(1)} days`, inline: true },
        { name: 'Status', value: 'Flagged for monitoring', inline: true },
      )
      .setFooter({ text: 'guardbot · anti-raid' })
      .setTimestamp();
    await sendLog(member.guild, embed);
  }

  // Verification gate
  if (verificationEnabled.get(guildId)) {
    await quarantineUser(member.guild, member, 'Awaiting verification');
  }
});

// ─── ANTI-NUKE: Channel Events ───────────────────────────────────────────────
client.on('channelDelete', async channel => {
  if (!channel.guild) return;
  if (!isAntiNukeEnabled(channel.guild.id)) return;

  const entry = await channel.guild.fetchAuditLogs({ type: AuditLogEvent.ChannelDelete, limit: 1 }).catch(() => null);
  const executor = entry?.entries?.first()?.executor;
  if (!executor || executor.id === client.user.id) return;

  // Skip if trusted (owner, maintenance mode, whitelisted, trusted admin/bot)
  if (shouldSkipAntiNuke(channel.guild, executor.id, executor)) return;

  // INSTANT BAN FOR UNTRUSTED BOTS - ZERO TOLERANCE
  if (executor.bot) {
    await instantBanBot(channel.guild, executor.id, `BOT NUKE DETECTED: Channel deletion (${channel.name})`);
    return;
  }

  trackAction(channel.guild.id, 'channelDelete');
  const actions = getActions(channel.guild.id, 'channelDelete');

  if (actions.length >= config.maxChannelDeletes) {
    await punishNuker(channel.guild, executor.id, `Mass channel deletion (${actions.length} channels)`);
  }
});

client.on('channelCreate', async channel => {
  if (!channel.guild) return;
  if (!isAntiNukeEnabled(channel.guild.id)) return;

  const entry = await channel.guild.fetchAuditLogs({ type: AuditLogEvent.ChannelCreate, limit: 1 }).catch(() => null);
  const executor = entry?.entries?.first()?.executor;
  if (!executor || executor.id === client.user.id) return;

  // Skip if trusted (owner, maintenance mode, whitelisted, trusted admin/bot)
  if (shouldSkipAntiNuke(channel.guild, executor.id, executor)) return;

  // INSTANT BAN FOR UNTRUSTED BOTS - ZERO TOLERANCE
  if (executor.bot) {
    await instantBanBot(channel.guild, executor.id, `BOT NUKE DETECTED: Mass channel creation (${channel.name})`);
    await channel.delete('[Anti-Nuke] Bot spam channel').catch(() => {});
    return;
  }

  trackAction(channel.guild.id, 'channelCreate');
  const actions = getActions(channel.guild.id, 'channelCreate');

  if (actions.length >= config.maxChannelCreates) {
    await punishNuker(channel.guild, executor.id, `Mass channel creation (${actions.length} channels)`);
    // Delete the spam channels
    await channel.delete('[Anti-Nuke] Spam channel').catch(() => {});
  }
});

// ─── ANTI-NUKE: Role Events ──────────────────────────────────────────────────
client.on('roleDelete', async role => {
  if (!isAntiNukeEnabled(role.guild.id)) return;

  const entry = await role.guild.fetchAuditLogs({ type: AuditLogEvent.RoleDelete, limit: 1 }).catch(() => null);
  const executor = entry?.entries?.first()?.executor;
  if (!executor || executor.id === client.user.id) return;

  // Skip if trusted (owner, maintenance mode, whitelisted, trusted admin/bot)
  if (shouldSkipAntiNuke(role.guild, executor.id, executor)) return;

  // INSTANT BAN FOR UNTRUSTED BOTS - ZERO TOLERANCE
  if (executor.bot) {
    await instantBanBot(role.guild, executor.id, `BOT NUKE DETECTED: Role deletion (${role.name})`);
    return;
  }

  trackAction(role.guild.id, 'roleDelete');
  const actions = getActions(role.guild.id, 'roleDelete');

  if (actions.length >= config.maxRoleDeletes) {
    await punishNuker(role.guild, executor.id, `Mass role deletion (${actions.length} roles)`);
  }
});

client.on('roleCreate', async role => {
  if (!isAntiNukeEnabled(role.guild.id)) return;

  const entry = await role.guild.fetchAuditLogs({ type: AuditLogEvent.RoleCreate, limit: 1 }).catch(() => null);
  const executor = entry?.entries?.first()?.executor;
  if (!executor || executor.id === client.user.id) return;

  // Skip if trusted (owner, maintenance mode, whitelisted, trusted admin/bot)
  if (shouldSkipAntiNuke(role.guild, executor.id, executor)) return;

  // INSTANT BAN FOR UNTRUSTED BOTS - ZERO TOLERANCE
  if (executor.bot) {
    await instantBanBot(role.guild, executor.id, `BOT NUKE DETECTED: Mass role creation (${role.name})`);
    await role.delete('[Anti-Nuke] Bot spam role').catch(() => {});
    return;
  }

  trackAction(role.guild.id, 'roleCreate');
  const actions = getActions(role.guild.id, 'roleCreate');

  if (actions.length >= config.maxRoleCreates) {
    await punishNuker(role.guild, executor.id, `Mass role creation (${actions.length} roles)`);
    await role.delete('[Anti-Nuke] Spam role').catch(() => {});
  }
});

// ─── ANTI-NUKE: Ban/Kick Events ──────────────────────────────────────────────
client.on('guildBanAdd', async ban => {
  if (!isAntiNukeEnabled(ban.guild.id)) return;

  const entry = await ban.guild.fetchAuditLogs({ type: AuditLogEvent.MemberBanAdd, limit: 1 }).catch(() => null);
  const executor = entry?.entries?.first()?.executor;
  if (!executor || executor.id === client.user.id) return;

  // Skip if trusted (owner, maintenance mode, whitelisted, trusted admin/bot)
  if (shouldSkipAntiNuke(ban.guild, executor.id, executor)) return;

  // INSTANT BAN FOR UNTRUSTED BOTS - ZERO TOLERANCE
  if (executor.bot) {
    await instantBanBot(ban.guild, executor.id, `BOT NUKE DETECTED: Mass banning users`);
    // Unban the victim
    await ban.guild.members.unban(ban.user.id, '[Anti-Nuke] Bot nuke victim restored').catch(() => {});
    return;
  }

  trackAction(ban.guild.id, 'ban');
  const actions = getActions(ban.guild.id, 'ban');

  if (actions.length >= config.maxBans) {
    await punishNuker(ban.guild, executor.id, `Mass banning (${actions.length} bans/min)`);
    // Unban the victim
    await ban.guild.members.unban(ban.user.id, '[Anti-Nuke] Mass ban victim').catch(() => {});
  }
});

client.on('guildMemberRemove', async member => {
  if (!isAntiNukeEnabled(member.guild.id)) return;

  const entry = await member.guild.fetchAuditLogs({ type: AuditLogEvent.MemberKick, limit: 1 }).catch(() => null);
  const log = entry?.entries?.first();
  if (!log || log.target?.id !== member.id) return;
  const executor = log.executor;
  if (!executor || executor.id === client.user.id) return;

  // Skip if trusted (owner, maintenance mode, whitelisted, trusted admin/bot)
  if (shouldSkipAntiNuke(member.guild, executor.id, executor)) return;

  // INSTANT BAN FOR UNTRUSTED BOTS - ZERO TOLERANCE
  if (executor.bot) {
    await instantBanBot(member.guild, executor.id, `BOT NUKE DETECTED: Mass kicking users`);
    return;
  }

  trackAction(member.guild.id, 'kick');
  const actions = getActions(member.guild.id, 'kick');

  if (actions.length >= config.maxKicks) {
    await punishNuker(member.guild, executor.id, `Mass kicking (${actions.length} kicks/min)`);
  }
});

// ─── ANTI-NUKE: Webhook Events ───────────────────────────────────────────────
client.on('webhooksUpdate', async channel => {
  if (!isAntiNukeEnabled(channel.guild.id)) return;

  const entry = await channel.guild.fetchAuditLogs({ type: AuditLogEvent.WebhookCreate, limit: 1 }).catch(() => null);
  const executor = entry?.entries?.first()?.executor;
  if (!executor || executor.id === client.user.id) return;

  // Skip if trusted (owner, maintenance mode, whitelisted, trusted admin/bot)
  if (shouldSkipAntiNuke(channel.guild, executor.id, executor)) return;

  // INSTANT BAN FOR UNTRUSTED BOTS - ZERO TOLERANCE
  if (executor.bot) {
    await instantBanBot(channel.guild, executor.id, `BOT NUKE DETECTED: Webhook spam`);
    // Delete malicious webhooks
    const webhooks = await channel.fetchWebhooks().catch(() => null);
    if (webhooks) {
      for (const wh of webhooks.values()) {
        if (wh.owner?.id === executor.id) {
          await wh.delete('[Anti-Nuke] Bot malicious webhook').catch(() => {});
        }
      }
    }
    return;
  }

  trackAction(channel.guild.id, 'webhook');
  const actions = getActions(channel.guild.id, 'webhook');

  if (actions.length >= config.maxWebhookCreates) {
    await punishNuker(channel.guild, executor.id, `Mass webhook creation (${actions.length} webhooks)`);
    
    // Delete malicious webhooks
    const webhooks = await channel.fetchWebhooks().catch(() => null);
    if (webhooks) {
      for (const wh of webhooks.values()) {
        if (wh.owner?.id === executor.id) {
          await wh.delete('[Anti-Nuke] Malicious webhook').catch(() => {});
        }
      }
    }
  }
});

// ─── ANTI-NUKE: Permission Changes ───────────────────────────────────────────
client.on('guildMemberUpdate', async (oldMember, newMember) => {
  if (!isAntiNukeEnabled(newMember.guild.id)) return;

  // Check if admin role was given
  const hadAdmin = oldMember.permissions.has(PermissionFlagsBits.Administrator);
  const hasAdmin = newMember.permissions.has(PermissionFlagsBits.Administrator);

  if (!hadAdmin && hasAdmin) {
    const entry = await newMember.guild.fetchAuditLogs({ type: AuditLogEvent.MemberRoleUpdate, limit: 1 }).catch(() => null);
    const executor = entry?.entries?.first()?.executor;
    if (!executor || executor.id === client.user.id || executor.id === newMember.guild.ownerId) return;

    trackAction(newMember.guild.id, 'permissionChange');
    const actions = getActions(newMember.guild.id, 'permissionChange');

    const embed = new EmbedBuilder()
      .setColor(0xff0000)
      .setAuthor({ name: '⚠️ ADMIN PERMISSION GRANTED' })
      .addFields(
        { name: 'Target', value: `<@${newMember.id}>`, inline: true },
        { name: 'By', value: `<@${executor.id}>`, inline: true },
      )
      .setFooter({ text: 'guardbot · permission monitor' })
      .setTimestamp();
    await sendLog(newMember.guild, embed);

    if (actions.length >= config.maxPermissionChanges) {
      await punishNuker(newMember.guild, executor.id, `Mass permission changes (${actions.length} admin grants)`);
      // Remove the admin from the target
      const adminRole = newMember.roles.cache.find(r => r.permissions.has(PermissionFlagsBits.Administrator));
      if (adminRole) {
        await newMember.roles.remove(adminRole, '[Anti-Nuke] Unauthorized admin grant').catch(() => {});
      }
    }
  }
});

// ─── SLASH COMMANDS ──────────────────────────────────────────────────────────
const commands = [
  {
    name: 'help',
    description: '📋 Show all bot commands and features',
  },
  {
    name: 'status',
    description: '📊 Show current protection status and threat levels',
  },
  {
    name: 'bio',
    description: '🤖 About GuardBot',
  },
  // Toggle commands
  {
    name: 'antinuke',
    description: '🔒 Toggle Anti-Nuke protection',
    options: [{ name: 'toggle', description: 'Enable or disable', type: 3, required: true, choices: [{ name: 'Enable', value: 'on' }, { name: 'Disable', value: 'off' }] }]
  },
  {
    name: 'antiraid',
    description: '🛡️ Toggle Anti-Raid protection',
    options: [{ name: 'toggle', description: 'Enable or disable', type: 3, required: true, choices: [{ name: 'Enable', value: 'on' }, { name: 'Disable', value: 'off' }] }]
  },
  {
    name: 'antispam',
    description: '🚫 Toggle Anti-Spam protection',
    options: [{ name: 'toggle', description: 'Enable or disable', type: 3, required: true, choices: [{ name: 'Enable', value: 'on' }, { name: 'Disable', value: 'off' }] }]
  },
  {
    name: 'antilink',
    description: '🔗 Toggle suspicious link protection',
    options: [{ name: 'toggle', description: 'Enable or disable', type: 3, required: true, choices: [{ name: 'Enable', value: 'on' }, { name: 'Disable', value: 'off' }] }]
  },
  {
    name: 'antimention',
    description: '📢 Toggle mass mention protection',
    options: [{ name: 'toggle', description: 'Enable or disable', type: 3, required: true, choices: [{ name: 'Enable', value: 'on' }, { name: 'Disable', value: 'off' }] }]
  },
  {
    name: 'dmwarnings',
    description: '📩 Toggle DM warnings to users',
    options: [{ name: 'toggle', description: 'Enable or disable', type: 3, required: true, choices: [{ name: 'Enable', value: 'on' }, { name: 'Disable', value: 'off' }] }]
  },
  {
    name: 'newacckick',
    description: '🔞 Toggle auto-kick for new accounts',
    options: [{ name: 'toggle', description: 'Enable or disable', type: 3, required: true, choices: [{ name: 'Enable', value: 'on' }, { name: 'Disable', value: 'off' }] }]
  },
  {
    name: 'raidmode',
    description: '🚨 Manually toggle raid mode',
    options: [{ name: 'toggle', description: 'Enable or disable', type: 3, required: true, choices: [{ name: 'Enable', value: 'on' }, { name: 'Disable', value: 'off' }] }]
  },
  // Emergency commands
  {
    name: 'lockdown',
    description: '🔐 Emergency server lockdown - prevents all messages',
    options: [{ name: 'toggle', description: 'Enable or disable', type: 3, required: true, choices: [{ name: 'Enable', value: 'on' }, { name: 'Disable', value: 'off' }] }]
  },
  {
    name: 'panic',
    description: '🚨 PANIC BUTTON - Instant lockdown + raid mode + kick recent joins',
  },
  // User management
  {
    name: 'whitelist',
    description: '✅ Whitelist a user from all detection',
    options: [{ name: 'user', description: 'User to whitelist', type: 6, required: true }]
  },
  {
    name: 'unwhitelist',
    description: '❌ Remove user from whitelist',
    options: [{ name: 'user', description: 'User to remove', type: 6, required: true }]
  },
  {
    name: 'quarantine',
    description: '🔒 Quarantine a suspicious user',
    options: [{ name: 'user', description: 'User to quarantine', type: 6, required: true }, { name: 'reason', description: 'Reason', type: 3, required: false }]
  },
  {
    name: 'unquarantine',
    description: '🔓 Release a user from quarantine',
    options: [{ name: 'user', description: 'User to release', type: 6, required: true }]
  },
  {
    name: 'threat',
    description: '📊 Check threat level of a user',
    options: [{ name: 'user', description: 'User to check', type: 6, required: true }]
  },
  {
    name: 'clearthreat',
    description: '🧹 Clear threat level of a user',
    options: [{ name: 'user', description: 'User to clear', type: 6, required: true }]
  },
  // Moderation
  {
    name: 'nuke',
    description: 'Mass delete messages in channel',
    options: [{ name: 'amount', description: 'Number of messages (1-100)', type: 4, required: true }]
  },
  {
    name: 'slowmode',
    description: 'Set channel slowmode',
    options: [{ name: 'seconds', description: 'Slowmode duration (0 to disable)', type: 4, required: true }]
  },
  // Maintenance Mode & Trust System
  {
    name: 'maintenance',
    description: 'Toggle maintenance mode - disables anti-nuke for admins',
    options: [
      { name: 'toggle', description: 'Enable or disable', type: 3, required: true, choices: [{ name: 'Enable (30 min)', value: 'on' }, { name: 'Disable', value: 'off' }] },
      { name: 'duration', description: 'Duration in minutes (default 30)', type: 4, required: false }
    ]
  },
  {
    name: 'trustadmin',
    description: 'Add admin to trusted list - immune to anti-nuke detection',
    options: [{ name: 'user', description: 'Admin to trust', type: 6, required: true }]
  },
  {
    name: 'untrustadmin',
    description: 'Remove admin from trusted list',
    options: [{ name: 'user', description: 'Admin to untrust', type: 6, required: true }]
  },
  {
    name: 'trustbot',
    description: 'Add bot to trusted list - immune to anti-nuke detection',
    options: [{ name: 'bot', description: 'Bot to trust (music bot, etc)', type: 6, required: true }]
  },
  {
    name: 'untrustbot',
    description: 'Remove bot from trusted list',
    options: [{ name: 'bot', description: 'Bot to untrust', type: 6, required: true }]
  },
  {
    name: 'trustlist',
    description: 'Show all trusted admins and bots',
  },
];

// ─── AUTO-CREATE MOD-LOGS ────────────────────────────────────────────────────
async function ensureModLogsChannel(guild) {
  let ch = guild.channels.cache.find(c => c.name === config.logChannelName && c.isTextBased());
  if (ch) {
    await ch.permissionOverwrites.edit(guild.roles.everyone, { ViewChannel: false }).catch(() => {});
    return ch;
  }

  ch = await guild.channels.create({
    name: config.logChannelName,
    type: 0,
    permissionOverwrites: [
      { id: guild.roles.everyone.id, deny: ['ViewChannel'] },
      { id: guild.members.me.id, allow: ['ViewChannel', 'SendMessages', 'EmbedLinks'] },
    ],
    topic: '⬡ GUARDBOT SECURITY LOGS · ALL THREATS LOGGED HERE',
    reason: 'GuardBot: Auto-created private mod-logs',
  }).catch(() => null);

  return ch;
}

// ─── READY EVENT ─────────────────────────────────────────────────────────────
client.once('ready', async () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██████╗  ██████╗ ████████╗  ║
║  ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝  ║
║  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██████╔╝██║   ██║   ██║     ║
║  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██╔══██╗██║   ██║   ██║     ║
║  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██████╔╝╚██████╔╝   ██║     ║
║   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═════╝  ╚═════╝    ╚═╝     ║
║                                                               ║
║   ✅ Bot Online: ${client.user.tag.padEnd(43)}║
║   🛡️  Servers Protected: ${String(client.guilds.cache.size).padEnd(37)}║
║   ⚡ All Systems: ACTIVE                                       ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
`);

  // Ensure mod-logs in all guilds
  for (const guild of client.guilds.cache.values()) {
    await ensureModLogsChannel(guild);
    await ensureQuarantineRole(guild);
  }

  // Status rotation
  let i = 0;
  const rotate = () => {
    const s = config.statuses[i % config.statuses.length];
    client.user.setPresence({ activities: [{ name: s.name, type: s.type }], status: 'dnd' }); // DND = Do Not Disturb (red)
    i++;
  };
  rotate();
  setInterval(rotate, 15000); // Faster rotation

  // Register slash commands
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
      .setAuthor({ name: '⬡ GUARDBOT · COMMAND LIST', iconURL: client.user.displayAvatarURL() })
      .setDescription('```ansi\n\u001b[1;31m24/7 MAXIMUM SECURITY PROTECTION\n\u001b[0;37mZero tolerance for raids, nukes & spam\n```')
      .addFields(
        { name: '🔒 ANTI-NUKE', value: '`/antinuke` · `/whitelist` · `/unwhitelist`', inline: true },
        { name: '🛡️ ANTI-RAID', value: '`/antiraid` · `/raidmode` · `/newacckick`', inline: true },
        { name: '🚫 ANTI-SPAM', value: '`/antispam` · `/antilink` · `/antimention`', inline: true },
        { name: '🚨 EMERGENCY', value: '`/lockdown` · `/panic` · `/nuke`', inline: true },
        { name: '👤 USER MGMT', value: '`/quarantine` · `/threat` · `/clearthreat`', inline: true },
        { name: '📊 INFO', value: '`/status` · `/bio` · `/slowmode`', inline: true },
        { name: '⚡ THRESHOLDS', value: `\`\`\`diff\n- Raid: ${config.joinRateLimit} joins/${config.joinRateWindow/1000}s\n- Nuke: ${config.maxBans} bans · ${config.maxChannelDeletes} ch-dels/min\n- Spam: ${config.maxInviteSpam} invite · ${config.maxMentionsPerMessage} mentions\n\`\`\``, inline: false },
      )
      .setFooter({ text: '⚠️ Admin permission required for all commands' })
      .setTimestamp();
    return interaction.reply({ embeds: [embed] });
  }

  // /bio
  if (commandName === 'bio') {
    const embed = new EmbedBuilder()
      .setColor(0x1a1a2e)
      .setAuthor({ name: '⬡ GUARDBOT · ABOUT', iconURL: client.user.displayAvatarURL() })
      .setThumbnail(client.user.displayAvatarURL())
      .setDescription('```ansi\n\u001b[1;31mMAXIMUM SECURITY DISCORD BOT\n\u001b[0;37mZero Tolerance · Instant Response\n```')
      .addFields(
        { name: '🔒 ANTI-NUKE', value: 'Mass ban/kick/delete detection\nPermission abuse monitoring\nAdmin compromise protection', inline: true },
        { name: '🛡️ ANTI-RAID', value: 'Join flood detection\nNew account filtering\nAuto-lockdown on severe raids', inline: true },
        { name: '🚫 ANTI-SPAM', value: 'Invite link blocking\nPhishing link detection\nMass mention protection\nEmoji/caps spam filter', inline: true },
        { name: '⚡ FEATURES', value: 'Threat level system\nDM warning system\nQuarantine system\nPanic button\nAuto-slowmode', inline: true },
        { name: '📊 VERSION', value: '2.0.0 ENHANCED\ndiscord.js v14', inline: true },
        { name: '🔥 MODE', value: 'ZERO TOLERANCE\nINSTANT RESPONSE', inline: true },
      )
      .setFooter({ text: 'guardbot · always watching · always protecting' })
      .setTimestamp();
    return interaction.reply({ embeds: [embed] });
  }

  // /status
  if (commandName === 'status') {
    const raidEnabled = isAntiRaidEnabled(guild.id);
    const nukeEnabled = isAntiNukeEnabled(guild.id);
    const spamEnabled = isAntiSpamEnabled(guild.id);
    const linkEnabled = isAntiLinkEnabled(guild.id);
    const mentionEnabled = isAntiMentionEnabled(guild.id);
    const inRaid = raidMode.get(guild.id) || false;
    const inLockdown = lockdownMode.get(guild.id) || false;
    const wl = whitelist.get(guild.id) || new Set();

    const embed = new EmbedBuilder()
      .setColor(inLockdown ? 0xff0000 : inRaid ? 0xff6600 : 0x00ff00)
      .setAuthor({ name: `⬡ GUARDBOT · STATUS${inLockdown ? ' · 🔐 LOCKDOWN' : inRaid ? ' · 🚨 RAID MODE' : ''}`, iconURL: client.user.displayAvatarURL() })
      .setDescription(inLockdown ? '```diff\n- SERVER IS IN LOCKDOWN\n- ALL MESSAGES BLOCKED\n```' : inRaid ? '```diff\n- RAID MODE ACTIVE\n- NEW JOINS BEING KICKED\n```' : '```diff\n+ ALL SYSTEMS OPERATIONAL\n```')
      .addFields(
        { name: '🔒 Anti-Nuke', value: nukeEnabled ? '```diff\n+ ON\n```' : '```diff\n- OFF\n```', inline: true },
        { name: '🛡️ Anti-Raid', value: raidEnabled ? '```diff\n+ ON\n```' : '```diff\n- OFF\n```', inline: true },
        { name: '🚫 Anti-Spam', value: spamEnabled ? '```diff\n+ ON\n```' : '```diff\n- OFF\n```', inline: true },
        { name: '🔗 Anti-Link', value: linkEnabled ? '```diff\n+ ON\n```' : '```diff\n- OFF\n```', inline: true },
        { name: '📢 Anti-Mention', value: mentionEnabled ? '```diff\n+ ON\n```' : '```diff\n- OFF\n```', inline: true },
        { name: '👶 New Acc Kick', value: config.newAccountKick ? '```diff\n- ON\n```' : '```diff\n+ OFF\n```', inline: true },
        { name: '✅ Whitelist', value: wl.size > 0 ? [...wl].map(id => `<@${id}>`).join(' ') : 'None', inline: false },
      )
      .setFooter({ text: `guardbot · ${guild.name}` })
      .setTimestamp();
    return interaction.reply({ embeds: [embed] });
  }

  // Admin-only commands
  if (!isAdmin) {
    return interaction.reply({ content: '❌ **ADMINISTRATOR** permission required.', ephemeral: true });
  }

  // Toggle commands
  if (commandName === 'antinuke') {
    const val = interaction.options.getString('toggle') === 'on';
    antiNukeEnabled.set(guild.id, val);
    return interaction.reply({ embeds: [new EmbedBuilder().setColor(0x1a1a2e).setDescription(`\`\`\`diff\n${val ? '+' : '-'} Anti-Nuke is now ${val ? 'ENABLED' : 'DISABLED'}\n\`\`\``).setTimestamp()] });
  }

  if (commandName === 'antiraid') {
    const val = interaction.options.getString('toggle') === 'on';
    antiRaidEnabled.set(guild.id, val);
    return interaction.reply({ embeds: [new EmbedBuilder().setColor(0x1a1a2e).setDescription(`\`\`\`diff\n${val ? '+' : '-'} Anti-Raid is now ${val ? 'ENABLED' : 'DISABLED'}\n\`\`\``).setTimestamp()] });
  }

  if (commandName === 'antispam') {
    const val = interaction.options.getString('toggle') === 'on';
    antiSpamEnabled.set(guild.id, val);
    return interaction.reply({ embeds: [new EmbedBuilder().setColor(0x1a1a2e).setDescription(`\`\`\`diff\n${val ? '+' : '-'} Anti-Spam is now ${val ? 'ENABLED' : 'DISABLED'}\n\`\`\``).setTimestamp()] });
  }

  if (commandName === 'antilink') {
    const val = interaction.options.getString('toggle') === 'on';
    antiLinkEnabled.set(guild.id, val);
    return interaction.reply({ embeds: [new EmbedBuilder().setColor(0x1a1a2e).setDescription(`\`\`\`diff\n${val ? '+' : '-'} Anti-Link is now ${val ? 'ENABLED' : 'DISABLED'}\n\`\`\``).setTimestamp()] });
  }

  if (commandName === 'antimention') {
    const val = interaction.options.getString('toggle') === 'on';
    antiMentionEnabled.set(guild.id, val);
    return interaction.reply({ embeds: [new EmbedBuilder().setColor(0x1a1a2e).setDescription(`\`\`\`diff\n${val ? '+' : '-'} Anti-Mention is now ${val ? 'ENABLED' : 'DISABLED'}\n\`\`\``).setTimestamp()] });
  }

  if (commandName === 'dmwarnings') {
    const val = interaction.options.getString('toggle') === 'on';
    dmWarningsEnabled.set(guild.id, val);
    return interaction.reply({ embeds: [new EmbedBuilder().setColor(0x1a1a2e).setDescription(`\`\`\`diff\n${val ? '+' : '-'} DM Warnings is now ${val ? 'ENABLED' : 'DISABLED'}\n\`\`\``).setTimestamp()] });
  }

  if (commandName === 'newacckick') {
    const val = interaction.options.getString('toggle') === 'on';
    config.newAccountKick = val;
    return interaction.reply({ embeds: [new EmbedBuilder().setColor(0x1a1a2e).setDescription(val ? '```diff\n- New account auto-kick ENABLED\n- Accounts under 7 days will be kicked\n```' : '```diff\n+ New account auto-kick DISABLED\n+ New accounts can join safely\n```').setTimestamp()] });
  }

  if (commandName === 'raidmode') {
    const val = interaction.options.getString('toggle') === 'on';
    raidMode.set(guild.id, val);
    return interaction.reply({ embeds: [new EmbedBuilder().setColor(val ? 0xff0000 : 0x00ff00).setDescription(val ? '```diff\n- ⚠ RAID MODE ACTIVATED\n- All new joins will be kicked\n```' : '```diff\n+ Raid mode deactivated\n+ Server back to normal\n```').setTimestamp()] });
  }

  // /lockdown
  if (commandName === 'lockdown') {
    const val = interaction.options.getString('toggle') === 'on';
    await toggleLockdown(guild, val);
    return interaction.reply({ embeds: [new EmbedBuilder().setColor(val ? 0xff0000 : 0x00ff00).setDescription(val ? '```diff\n- 🔐 SERVER LOCKDOWN ACTIVATED\n- All channels locked\n- No messages allowed\n```' : '```diff\n+ Lockdown lifted\n+ Server restored\n```').setTimestamp()] });
  }

  // /panic - EMERGENCY
  if (commandName === 'panic') {
    await interaction.deferReply();
    
    // 1. Enable lockdown
    await toggleLockdown(guild, true);
    
    // 2. Enable raid mode
    raidMode.set(guild.id, true);
    
    // 3. Kick all members who joined in last 10 minutes
    const tenMinAgo = Date.now() - 600000;
    let kicked = 0;
    
    for (const member of guild.members.cache.values()) {
      if (member.joinedTimestamp > tenMinAgo && !member.permissions.has(PermissionFlagsBits.Administrator)) {
        await member.kick('[PANIC] Emergency protocol').catch(() => {});
        kicked++;
      }
    }

    const embed = new EmbedBuilder()
      .setColor(0xff0000)
      .setAuthor({ name: '🚨 PANIC BUTTON ACTIVATED' })
      .setDescription('```diff\n- EMERGENCY PROTOCOL ENGAGED\n```')
      .addFields(
        { name: 'Lockdown', value: '```diff\n- ACTIVE\n```', inline: true },
        { name: 'Raid Mode', value: '```diff\n- ACTIVE\n```', inline: true },
        { name: 'Recent Kicks', value: `\`\`\`diff\n- ${kicked} members\n\`\`\``, inline: true },
      )
      .setFooter({ text: 'Use /lockdown off and /raidmode off to restore' })
      .setTimestamp();
    return interaction.editReply({ embeds: [embed] });
  }

  // /whitelist
  if (commandName === 'whitelist') {
    const user = interaction.options.getUser('user');
    if (!whitelist.has(guild.id)) whitelist.set(guild.id, new Set());
    whitelist.get(guild.id).add(user.id);
    return interaction.reply({ embeds: [new EmbedBuilder().setColor(0x00ff00).setDescription(`\`\`\`diff\n+ ${user.tag} added to whitelist\n+ Exempt from all detection\n\`\`\``).setTimestamp()] });
  }

  // /unwhitelist
  if (commandName === 'unwhitelist') {
    const user = interaction.options.getUser('user');
    whitelist.get(guild.id)?.delete(user.id);
    return interaction.reply({ embeds: [new EmbedBuilder().setColor(0xff6600).setDescription(`\`\`\`diff\n- ${user.tag} removed from whitelist\n\`\`\``).setTimestamp()] });
  }

  // /quarantine
  if (commandName === 'quarantine') {
    const user = interaction.options.getUser('user');
    const reason = interaction.options.getString('reason') || 'Manual quarantine';
    const targetMember = await guild.members.fetch(user.id).catch(() => null);
    
    if (!targetMember) return interaction.reply({ content: '❌ User not found.', ephemeral: true });
    
    const success = await quarantineUser(guild, targetMember, reason);
    return interaction.reply({ embeds: [new EmbedBuilder().setColor(success ? 0x808080 : 0xff0000).setDescription(success ? `\`\`\`diff\n- ${user.tag} has been quarantined\n- Reason: ${reason}\n\`\`\`` : '```diff\n- Failed to quarantine user\n```').setTimestamp()] });
  }

  // /unquarantine
  if (commandName === 'unquarantine') {
    const user = interaction.options.getUser('user');
    const targetMember = await guild.members.fetch(user.id).catch(() => null);
    
    if (!targetMember) return interaction.reply({ content: '❌ User not found.', ephemeral: true });
    
    const role = guild.roles.cache.find(r => r.name === config.quarantineRoleName);
    if (role) await targetMember.roles.remove(role).catch(() => {});
    quarantinedUsers.delete(user.id);
    
    return interaction.reply({ embeds: [new EmbedBuilder().setColor(0x00ff00).setDescription(`\`\`\`diff\n+ ${user.tag} released from quarantine\n\`\`\``).setTimestamp()] });
  }

  // /threat
  if (commandName === 'threat') {
    const user = interaction.options.getUser('user');
    const threat = getThreatLevel(user.id);
    const score = getThreatScore(user.id);
    
    const embed = new EmbedBuilder()
      .setColor(score > 10 ? 0xff0000 : score > 5 ? 0xff6600 : 0x00ff00)
      .setAuthor({ name: `📊 Threat Level: ${user.tag}` })
      .addFields(
        { name: 'Score', value: `\`${score}\``, inline: true },
        { name: 'Warnings', value: `\`${threat.warnings}\``, inline: true },
        { name: 'Mutes', value: `\`${threat.mutes}\``, inline: true },
        { name: 'Kicks', value: `\`${threat.kicks}\``, inline: true },
        { name: 'Risk Level', value: score > 10 ? '```diff\n- HIGH RISK\n```' : score > 5 ? '```fix\nMEDIUM RISK\n```' : '```diff\n+ LOW RISK\n```', inline: false },
      )
      .setTimestamp();
    return interaction.reply({ embeds: [embed] });
  }

  // /clearthreat
  if (commandName === 'clearthreat') {
    const user = interaction.options.getUser('user');
    threatLevel.delete(user.id);
    return interaction.reply({ embeds: [new EmbedBuilder().setColor(0x00ff00).setDescription(`\`\`\`diff\n+ Threat level cleared for ${user.tag}\n\`\`\``).setTimestamp()] });
  }

  // /nuke (purge messages)
  if (commandName === 'nuke') {
    const amount = interaction.options.getInteger('amount');
    if (amount < 1 || amount > 100) return interaction.reply({ content: '❌ Amount must be 1-100', ephemeral: true });
    
    await interaction.deferReply({ ephemeral: true });
    const deleted = await interaction.channel.bulkDelete(amount, true).catch(() => null);
    
    const embed = new EmbedBuilder()
      .setColor(0xff6600)
      .setAuthor({ name: '💣 MESSAGES NUKED' })
      .addFields(
        { name: 'Channel', value: `<#${interaction.channel.id}>`, inline: true },
        { name: 'Deleted', value: `${deleted?.size || 0} messages`, inline: true },
        { name: 'By', value: `<@${interaction.user.id}>`, inline: true },
      )
      .setTimestamp();
    await sendLog(guild, embed);
    
    return interaction.editReply({ content: `✅ Deleted ${deleted?.size || 0} messages.` });
  }

  // /slowmode
  if (commandName === 'slowmode') {
    const seconds = interaction.options.getInteger('seconds');
    await interaction.channel.setRateLimitPerUser(seconds).catch(() => {});
    return interaction.reply({ embeds: [new EmbedBuilder().setColor(0x1a1a2e).setDescription(`\`\`\`diff\n${seconds > 0 ? '-' : '+'} Slowmode set to ${seconds}s\n\`\`\``).setTimestamp()] });
  }

  // /maintenance - Temporarily disable anti-nuke for server organizing
  if (commandName === 'maintenance') {
    const val = interaction.options.getString('toggle') === 'on';
    const duration = interaction.options.getInteger('duration') || 30; // Default 30 minutes

    if (val) {
      const expiry = Date.now() + (duration * 60 * 1000);
      maintenanceMode.set(guild.id, { enabled: true, expiry });
      
      const embed = new EmbedBuilder()
        .setColor(0xffcc00)
        .setAuthor({ name: 'MAINTENANCE MODE ENABLED' })
        .setDescription('```fix\nAnti-nuke protection temporarily disabled\nAdmins can now reorganize the server safely\n```')
        .addFields(
          { name: 'Duration', value: `${duration} minutes`, inline: true },
          { name: 'Expires', value: `<t:${Math.floor(expiry / 1000)}:R>`, inline: true },
        )
        .setFooter({ text: 'Use /maintenance off to disable early' })
        .setTimestamp();
      
      await sendLog(guild, embed);
      return interaction.reply({ embeds: [embed] });
    } else {
      maintenanceMode.set(guild.id, { enabled: false, expiry: null });
      return interaction.reply({ embeds: [new EmbedBuilder().setColor(0x00ff00).setDescription('```diff\n+ Maintenance mode DISABLED\n+ Anti-nuke protection restored\n```').setTimestamp()] });
    }
  }

  // /trustadmin - Add admin to trusted list
  if (commandName === 'trustadmin') {
    const user = interaction.options.getUser('user');
    const targetMember = await guild.members.fetch(user.id).catch(() => null);
    
    if (!targetMember) return interaction.reply({ content: 'User not found.', ephemeral: true });
    if (!targetMember.permissions.has(PermissionFlagsBits.Administrator)) {
      return interaction.reply({ content: 'User must be an administrator.', ephemeral: true });
    }
    
    if (!trustedAdmins.has(guild.id)) trustedAdmins.set(guild.id, new Set());
    trustedAdmins.get(guild.id).add(user.id);
    
    const embed = new EmbedBuilder()
      .setColor(0x00ff00)
      .setDescription(`\`\`\`diff\n+ ${user.tag} added to trusted admins\n+ Immune to anti-nuke detection\n\`\`\``)
      .setFooter({ text: 'Trusted admins can reorganize server without triggering alerts' })
      .setTimestamp();
    return interaction.reply({ embeds: [embed] });
  }

  // /untrustadmin - Remove admin from trusted list
  if (commandName === 'untrustadmin') {
    const user = interaction.options.getUser('user');
    trustedAdmins.get(guild.id)?.delete(user.id);
    return interaction.reply({ embeds: [new EmbedBuilder().setColor(0xff6600).setDescription(`\`\`\`diff\n- ${user.tag} removed from trusted admins\n\`\`\``).setTimestamp()] });
  }

  // /trustbot - Add bot to trusted list (music bots, etc)
  if (commandName === 'trustbot') {
    const bot = interaction.options.getUser('bot');
    
    if (!bot.bot) return interaction.reply({ content: 'Target must be a bot.', ephemeral: true });
    
    if (!trustedBots.has(guild.id)) trustedBots.set(guild.id, new Set());
    trustedBots.get(guild.id).add(bot.id);
    
    const embed = new EmbedBuilder()
      .setColor(0x00ff00)
      .setDescription(`\`\`\`diff\n+ ${bot.tag} added to trusted bots\n+ Will NOT be banned for admin actions\n\`\`\``)
      .setFooter({ text: 'Only trust bots you verified! Compromised bots can still nuke.' })
      .setTimestamp();
    return interaction.reply({ embeds: [embed] });
  }

  // /untrustbot - Remove bot from trusted list
  if (commandName === 'untrustbot') {
    const bot = interaction.options.getUser('bot');
    trustedBots.get(guild.id)?.delete(bot.id);
    return interaction.reply({ embeds: [new EmbedBuilder().setColor(0xff6600).setDescription(`\`\`\`diff\n- ${bot.tag} removed from trusted bots\n- Will be banned instantly for nuke attempts\n\`\`\``).setTimestamp()] });
  }

  // /trustlist - Show all trusted admins and bots
  if (commandName === 'trustlist') {
    const admins = trustedAdmins.get(guild.id) || new Set();
    const bots = trustedBots.get(guild.id) || new Set();
    const wl = whitelist.get(guild.id) || new Set();
    const maint = maintenanceMode.get(guild.id);
    
    const embed = new EmbedBuilder()
      .setColor(0x1a1a2e)
      .setAuthor({ name: 'TRUSTED USERS & SETTINGS' })
      .addFields(
        { name: 'Maintenance Mode', value: isMaintenanceMode(guild.id) ? `\`\`\`diff\n- ACTIVE (expires <t:${Math.floor(maint.expiry / 1000)}:R>)\n\`\`\`` : '```diff\n+ INACTIVE\n```', inline: false },
        { name: 'Trusted Admins', value: admins.size > 0 ? [...admins].map(id => `<@${id}>`).join('\n') : 'None', inline: true },
        { name: 'Trusted Bots', value: bots.size > 0 ? [...bots].map(id => `<@${id}>`).join('\n') : 'None', inline: true },
        { name: 'Whitelisted Users', value: wl.size > 0 ? [...wl].map(id => `<@${id}>`).join('\n') : 'None', inline: true },
      )
      .setFooter({ text: 'Trusted users are immune to anti-nuke detection' })
      .setTimestamp();
    return interaction.reply({ embeds: [embed] });
  }
});

// ─── START BOT ───────────────────────────────────────────────────────────────
client.login(config.token);

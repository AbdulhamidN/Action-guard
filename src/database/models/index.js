const sequelize = require('../index');
const initUserModel = require('./User');
const initSessionModel = require('./Session');
const initDeviceModel = require('./Device');
const initSecurityEventModel = require('./SecurityEvent');
const initBehavioralBaselineModel = require('./BehavioralBaseline');
const initActionSequenceModel = require('./ActionSequence');
const initSequenceEventModel = require('./SequenceEvent');
const initRiskAssessmentModel = require('./RiskAssessment');
const initPolicyDecisionModel = require('./PolicyDecision');
const initElevationAuditLogModel = require('./ElevationAuditLog');

const User = initUserModel(sequelize);
const Session = initSessionModel(sequelize);
const Device = initDeviceModel(sequelize);
const SecurityEvent = initSecurityEventModel(sequelize);
const BehavioralBaseline = initBehavioralBaselineModel(sequelize);
const ActionSequence = initActionSequenceModel(sequelize);
const SequenceEvent = initSequenceEventModel(sequelize);
const RiskAssessment = initRiskAssessmentModel(sequelize);
const PolicyDecision = initPolicyDecisionModel(sequelize);
const ElevationAuditLog = initElevationAuditLogModel(sequelize);

// Associations
User.hasMany(Session, {
  foreignKey: 'user_id',
  as: 'sessions',
  onDelete: 'CASCADE'
});
Session.belongsTo(User, {
  foreignKey: 'user_id',
  as: 'user'
});

User.hasMany(Device, {
  foreignKey: 'user_id',
  as: 'devices',
  onDelete: 'CASCADE'
});
Device.belongsTo(User, {
  foreignKey: 'user_id',
  as: 'user'
});

User.hasMany(SecurityEvent, {
  foreignKey: 'user_id',
  as: 'securityEvents',
  onDelete: 'CASCADE'
});
SecurityEvent.belongsTo(User, {
  foreignKey: 'user_id',
  as: 'user'
});

Session.hasMany(SecurityEvent, {
  foreignKey: 'session_id',
  as: 'securityEvents',
  onDelete: 'SET NULL'
});
SecurityEvent.belongsTo(Session, {
  foreignKey: 'session_id',
  as: 'session'
});

// 1-to-1 User <-> BehavioralBaseline
User.hasOne(BehavioralBaseline, {
  foreignKey: 'user_id',
  as: 'baseline',
  onDelete: 'CASCADE'
});
BehavioralBaseline.belongsTo(User, {
  foreignKey: 'user_id',
  as: 'user'
});

// Module 5.1: ActionSequence & SequenceEvent Associations
User.hasMany(ActionSequence, {
  foreignKey: 'user_id',
  as: 'actionSequences',
  onDelete: 'CASCADE'
});
ActionSequence.belongsTo(User, {
  foreignKey: 'user_id',
  as: 'user'
});

Session.hasMany(ActionSequence, {
  foreignKey: 'session_id',
  as: 'actionSequences',
  onDelete: 'SET NULL'
});
ActionSequence.belongsTo(Session, {
  foreignKey: 'session_id',
  as: 'session'
});

ActionSequence.belongsToMany(SecurityEvent, {
  through: SequenceEvent,
  foreignKey: 'sequence_id',
  otherKey: 'event_id',
  as: 'events'
});
SecurityEvent.belongsToMany(ActionSequence, {
  through: SequenceEvent,
  foreignKey: 'event_id',
  otherKey: 'sequence_id',
  as: 'sequences'
});

ActionSequence.hasMany(SequenceEvent, {
  foreignKey: 'sequence_id',
  as: 'sequenceEvents',
  onDelete: 'CASCADE'
});
SequenceEvent.belongsTo(ActionSequence, {
  foreignKey: 'sequence_id',
  as: 'sequence'
});

SecurityEvent.hasMany(SequenceEvent, {
  foreignKey: 'event_id',
  as: 'sequenceEvents',
  onDelete: 'CASCADE'
});
SequenceEvent.belongsTo(SecurityEvent, {
  foreignKey: 'event_id',
  as: 'securityEvent'
});

// Module 6.3a: RiskAssessment Associations
User.hasMany(RiskAssessment, {
  foreignKey: 'user_id',
  as: 'riskAssessments',
  onDelete: 'CASCADE'
});
RiskAssessment.belongsTo(User, {
  foreignKey: 'user_id',
  as: 'user'
});

Session.hasMany(RiskAssessment, {
  foreignKey: 'session_id',
  as: 'riskAssessments',
  onDelete: 'SET NULL'
});
RiskAssessment.belongsTo(Session, {
  foreignKey: 'session_id',
  as: 'session'
});

SecurityEvent.hasMany(RiskAssessment, {
  foreignKey: 'event_id',
  as: 'riskAssessments',
  onDelete: 'SET NULL'
});
RiskAssessment.belongsTo(SecurityEvent, {
  foreignKey: 'event_id',
  as: 'securityEvent'
});

// Module 10b: PolicyDecision & ElevationAuditLog Associations
User.hasMany(PolicyDecision, {
  foreignKey: 'user_id',
  as: 'policyDecisions',
  onDelete: 'CASCADE'
});
PolicyDecision.belongsTo(User, {
  foreignKey: 'user_id',
  as: 'user'
});

Session.hasMany(PolicyDecision, {
  foreignKey: 'session_id',
  as: 'policyDecisions',
  onDelete: 'SET NULL'
});
PolicyDecision.belongsTo(Session, {
  foreignKey: 'session_id',
  as: 'session'
});

SecurityEvent.hasMany(PolicyDecision, {
  foreignKey: 'event_id',
  as: 'policyDecisions',
  onDelete: 'SET NULL'
});
PolicyDecision.belongsTo(SecurityEvent, {
  foreignKey: 'event_id',
  as: 'securityEvent'
});

RiskAssessment.hasMany(PolicyDecision, {
  foreignKey: 'risk_assessment_id',
  as: 'policyDecisions',
  onDelete: 'SET NULL'
});
PolicyDecision.belongsTo(RiskAssessment, {
  foreignKey: 'risk_assessment_id',
  as: 'riskAssessment'
});

User.hasMany(ElevationAuditLog, {
  foreignKey: 'user_id',
  as: 'elevationAuditLogs',
  onDelete: 'CASCADE'
});
ElevationAuditLog.belongsTo(User, {
  foreignKey: 'user_id',
  as: 'user'
});

Session.hasMany(ElevationAuditLog, {
  foreignKey: 'session_id',
  as: 'elevationAuditLogs',
  onDelete: 'SET NULL'
});
ElevationAuditLog.belongsTo(Session, {
  foreignKey: 'session_id',
  as: 'session'
});

module.exports = {
  sequelize,
  User,
  Session,
  Device,
  SecurityEvent,
  BehavioralBaseline,
  ActionSequence,
  SequenceEvent,
  RiskAssessment,
  PolicyDecision,
  ElevationAuditLog
};

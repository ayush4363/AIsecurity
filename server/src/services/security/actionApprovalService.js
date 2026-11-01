/**
 * Action Approval & Permission Guard
 * Prevents autonomous execution of sensitive operations (sending email, downloading files,
 * calling external APIs, deleting data) without explicit human-in-the-loop confirmation.
 */

class ActionApprovalService {
  constructor() {
    this.pendingApprovals = [];
    this.approvalHistory = [];
  }

  createActionRequest({ type, description, parameters, requestedBy, riskLevel = 'HIGH' }) {
    const action = {
      id: `act-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
      type, // 'SEND_EMAIL' | 'EXTERNAL_API_CALL' | 'FILE_WRITE' | 'BROWSE_UNTRUSTED_URL'
      description,
      parameters,
      requestedBy: requestedBy || 'AI Task Assistant',
      riskLevel,
      status: 'PENDING_APPROVAL',
      createdAt: new Date().toISOString()
    };

    this.pendingApprovals.push(action);
    return action;
  }

  getPending() {
    return this.pendingApprovals;
  }

  getHistory() {
    return this.approvalHistory;
  }

  resolveAction(actionId, approved, userComment = '') {
    const index = this.pendingApprovals.findIndex(a => a.id === actionId);
    if (index === -1) {
      throw new Error('Action request not found or already resolved.');
    }

    const action = this.pendingApprovals.splice(index, 1)[0];
    action.status = approved ? 'APPROVED_BY_USER' : 'REJECTED_BY_USER';
    action.resolvedAt = new Date().toISOString();
    action.userComment = userComment;

    this.approvalHistory.unshift(action);
    return action;
  }
}

export const actionApprovalService = new ActionApprovalService();

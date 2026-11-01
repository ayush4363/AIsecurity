import React, { useState, useEffect, useCallback } from 'react';
import DOMPurify from 'dompurify';
import {
  Mail,
  Search,
  RefreshCw,
  Shield,
  CheckCircle2,
  AlertOctagon,
  ExternalLink,
  Lock,
  Paperclip,
  ChevronLeft,
  ChevronRight,
  LogOut,
  Sparkles,
  Code,
  FileText,
  AlertTriangle,
  User,
  Clock,
  ArrowRight,
  Eye,
  Check,
  X
} from 'lucide-react';
import { api } from '../services/api';

export default function GmailReader({ onSecurityEvent }) {
  // Gmail Connection State
  const [gmailStatus, setGmailStatus] = useState({
    connected: false,
    email: null,
    name: null,
    picture: null,
    connectedAt: null
  });
  const [isCheckingStatus, setIsCheckingStatus] = useState(true);
  const [isDisconnecting, setIsDisconnecting] = useState(false);

  // Email List State
  const [emails, setEmails] = useState([]);
  const [selectedEmail, setSelectedEmail] = useState(null);
  const [isLoadingEmails, setIsLoadingEmails] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeFilter, setActiveFilter] = useState('ALL'); // ALL, UNREAD, FLAGGED

  // Pagination State
  const [pageToken, setPageToken] = useState(null);
  const [nextPageToken, setNextPageToken] = useState(null);
  const [tokenStack, setTokenStack] = useState([]);
  const [pageNumber, setPageNumber] = useState(1);

  // Email Details & Security State
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);
  const [emailDetail, setEmailDetail] = useState(null);
  const [viewMode, setViewMode] = useState('html'); // 'html' or 'text'
  const [analyzingEmail, setAnalyzingEmail] = useState(false);
  const [analysisReport, setAnalysisReport] = useState(null);

  // Notifications
  const [notification, setNotification] = useState(null);

  // 1. Check URL parameters for OAuth redirect callback status
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const gmailParam = params.get('gmail');
    const emailParam = params.get('email');
    const errorParam = params.get('gmail_error');

    if (gmailParam === 'connected') {
      setNotification({
        type: 'success',
        message: `Google Account ${emailParam ? `(${emailParam})` : ''} connected successfully with Read-Only security scope.`
      });
      // Clean query params from URL without reload
      const cleanUrl = window.location.pathname + (window.location.hash || '#email');
      window.history.replaceState({}, document.title, cleanUrl);
    } else if (errorParam) {
      setNotification({
        type: 'error',
        message: `Failed to connect Google account: ${decodeURIComponent(errorParam)}`
      });
      const cleanUrl = window.location.pathname + (window.location.hash || '#email');
      window.history.replaceState({}, document.title, cleanUrl);
    }
  }, []);

  // 2. Load Gmail connection status
  const loadStatus = useCallback(async () => {
    setIsCheckingStatus(true);
    try {
      const res = await api.getGmailStatus();
      if (res.success && res.status) {
        setGmailStatus(res.status);
      }
    } catch (err) {
      console.warn('[Gmail] Could not load status:', err.message);
    } finally {
      setIsCheckingStatus(false);
    }
  }, []);

  useEffect(() => {
    loadStatus();
  }, [loadStatus]);

  // 3. Load Emails (either from live Gmail or fallback)
  const loadMessages = useCallback(async (token = null, query = searchQuery) => {
    setIsLoadingEmails(true);
    try {
      if (gmailStatus.connected) {
        const res = await api.getGmailMessages({
          maxResults: 12,
          pageToken: token || undefined,
          q: query.trim() || undefined
        });

        if (res.success) {
          setEmails(res.messages || []);
          setNextPageToken(res.nextPageToken || null);
          if (res.messages && res.messages.length > 0 && !selectedEmail) {
            handleSelectEmail(res.messages[0].id);
          }
        }
      } else {
        // Fallback to protected demo emails
        const res = await api.getEmails();
        if (res.success) {
          setEmails(res.emails || []);
          if (res.emails && res.emails.length > 0 && !selectedEmail) {
            handleSelectEmail(res.emails[0].id);
          }
        }
      }
    } catch (err) {
      console.warn('[Gmail] Error fetching messages:', err.message);
    } finally {
      setIsLoadingEmails(false);
    }
  }, [gmailStatus.connected, searchQuery]);

  useEffect(() => {
    if (!isCheckingStatus) {
      loadMessages();
    }
  }, [isCheckingStatus, gmailStatus.connected, loadMessages]);

  // 4. Handle Email Selection
  const handleSelectEmail = async (emailId) => {
    const listMatch = emails.find(e => e.id === emailId);
    setSelectedEmail(listMatch || { id: emailId });
    setAnalysisReport(null);
    setIsLoadingDetail(true);

    try {
      if (gmailStatus.connected) {
        const res = await api.getGmailMessage(emailId);
        if (res.success && res.message) {
          setEmailDetail(res.message);
          if (res.message.security) {
            setAnalysisReport(res.message.security);
          }
        }
      } else {
        const res = await api.getEmail(emailId);
        if (res.success && res.email) {
          setEmailDetail({
            ...res.email,
            bodyText: res.email.body,
            bodyHtml: `<p>${res.email.body.replace(/\n/g, '<br/>')}</p>`,
            attachments: []
          });
        }
      }
    } catch (err) {
      console.error('[Gmail] Error fetching email details:', err.message);
    } finally {
      setIsLoadingDetail(false);
    }
  };

  // 5. Connect Gmail Handler
  const handleConnectGmail = async () => {
    try {
      const res = await api.getGmailAuthUrl();
      if (res.success && res.authUrl) {
        window.location.href = res.authUrl;
      } else {
        // Fallback direct endpoint redirect
        window.location.href = 'http://localhost:5001/api/gmail/auth?redirect=true';
      }
    } catch (err) {
      // Fallback direct endpoint redirect
      window.location.href = 'http://localhost:5001/api/gmail/auth?redirect=true';
    }
  };

  // 6. Disconnect Gmail Handler
  const handleDisconnect = async () => {
    if (!window.confirm('Are you sure you want to disconnect your Gmail account from The Possessed Butler?')) {
      return;
    }

    setIsDisconnecting(true);
    try {
      const res = await api.disconnectGmail();
      if (res.success) {
        setGmailStatus({
          connected: false,
          email: null,
          name: null,
          picture: null,
          connectedAt: null
        });
        setSelectedEmail(null);
        setEmailDetail(null);
        setNotification({
          type: 'success',
          message: 'Gmail disconnected. Restored Protected Demo Mailbox.'
        });
        loadMessages();
      }
    } catch (err) {
      setNotification({
        type: 'error',
        message: `Failed to disconnect Gmail: ${err.message}`
      });
    } finally {
      setIsDisconnecting(false);
    }
  };

  // 7. Pagination Handlers
  const handleNextPage = () => {
    if (!nextPageToken) return;
    setTokenStack(prev => [...prev, pageToken]);
    setPageToken(nextPageToken);
    setPageNumber(prev => prev + 1);
    loadMessages(nextPageToken);
  };

  const handlePrevPage = () => {
    if (tokenStack.length === 0) return;
    const prevToken = tokenStack[tokenStack.length - 1];
    setTokenStack(prev => prev.slice(0, -1));
    setPageToken(prevToken);
    setPageNumber(prev => Math.max(1, prev - 1));
    loadMessages(prevToken);
  };

  // 8. Search Submission
  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPageToken(null);
    setTokenStack([]);
    setPageNumber(1);
    loadMessages(null, searchQuery);
  };

  // 9. Analyze Email with Butler AI Security
  const handleAnalyzeWithButler = async () => {
    if (!selectedEmail) return;
    setAnalyzingEmail(true);

    try {
      if (gmailStatus.connected) {
        const res = await api.scanEmailPayload({
          id: emailDetail?.id || selectedEmail.id,
          subject: emailDetail?.subject || selectedEmail.subject,
          from: emailDetail?.from || selectedEmail.from,
          senderEmail: emailDetail?.from || selectedEmail.from,
          sender: emailDetail?.senderName || selectedEmail.senderName,
          body: emailDetail?.bodyText || emailDetail?.snippet || selectedEmail.snippet,
          headers: emailDetail?.headers
        });

        const report = res.result || res.analysis;
        if (report) {
          setAnalysisReport(report);
          if (onSecurityEvent) onSecurityEvent(report);
        }
      } else {
        const res = await api.analyzeEmail(selectedEmail.id);
        if (res.success) {
          setAnalysisReport({
            isSafe: res.result.analysis.isSafe,
            riskScore: res.result.analysis.riskScore,
            threats: res.result.analysis.threats,
            explanation: res.result.safeSummary
          });
          if (onSecurityEvent) onSecurityEvent(res.result.analysis);
        }
      }
    } catch (err) {
      console.error('[Gmail Analysis Error]', err.message);
    } finally {
      setAnalyzingEmail(false);
    }
  };

  // Filter Click Handler
  const handleFilterClick = (filter) => {
    setActiveFilter(filter);
    setPageToken(null);
    setTokenStack([]);
    setPageNumber(1);
    if (filter === 'SPAM') {
      loadMessages(null, 'in:spam');
    } else if (activeFilter === 'SPAM') {
      loadMessages(null, searchQuery);
    }
  };

  // Filtered emails list
  const filteredEmails = emails.filter(e => {
    if (activeFilter === 'UNREAD') return !e.isRead;
    if (activeFilter === 'NEEDS_REVIEW') return e.securityStatus === 'NEEDS_REVIEW' || (e.riskScore >= 20 && e.riskScore < 50);
    if (activeFilter === 'FLAGGED') return !e.isSafe || e.securityStatus === 'THREAT_INTERCEPTED' || e.securityStatus === 'SUSPICIOUS';
    if (activeFilter === 'SPAM') return e.isSpam || e.labels?.includes('SPAM');
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Toast Notification */}
      {notification && (
        <div
          className={`p-4 rounded-2xl border flex items-center justify-between text-xs sm:text-sm font-semibold transition ${
            notification.type === 'success'
              ? 'bg-emerald-950/70 border-emerald-500/40 text-emerald-200'
              : 'bg-rose-950/70 border-rose-500/40 text-rose-200'
          }`}
        >
          <div className="flex items-center gap-2.5">
            {notification.type === 'success' ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
            ) : (
              <AlertOctagon className="w-5 h-5 text-rose-400 flex-shrink-0" />
            )}
            <span>{notification.message}</span>
          </div>
          <button
            onClick={() => setNotification(null)}
            className="text-white/60 hover:text-white text-xs px-2 py-1 rounded-lg bg-white/10"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Gmail OAuth Connection Header Card */}
      <div className="glass-panel-purple p-6 sm:p-7 rounded-[32px] border border-white/20 relative overflow-hidden">
        <div className="absolute top-0 right-0 -mr-16 -mt-16 w-64 h-64 bg-brand-yellow/10 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6 relative z-10">
          <div className="flex items-start sm:items-center gap-4">
            <div className="w-14 h-14 rounded-2xl bg-white/10 border border-white/20 flex items-center justify-center flex-shrink-0 shadow-inner">
              <Mail className="w-7 h-7 text-brand-yellow" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-xl sm:text-2xl font-black text-white">
                  Gmail Integration & Security Guard
                </h2>
                {gmailStatus.connected ? (
                  <span className="inline-flex items-center gap-1.5 px-3 py-0.5 rounded-full text-[11px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                    Live Gmail Connected
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 px-3 py-0.5 rounded-full text-[11px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                    <span className="w-2 h-2 rounded-full bg-amber-400" />
                    Sandbox Mailbox
                  </span>
                )}
              </div>
              <p className="text-xs sm:text-sm text-brand-cream/80 mt-1">
                {gmailStatus.connected
                  ? `Authenticated as ${gmailStatus.name || 'Google User'} (${gmailStatus.email}). All incoming emails protected by AI Action Firewall.`
                  : gmailStatus.scopeNeedsUpgrade
                  ? `Connected as ${gmailStatus.email}, but Gmail read-only permission is required. Click below to grant mailbox access.`
                  : 'Connect your real Google account via official OAuth 2.0 to inspect live emails under Zero-Trust Butler protection.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 w-full md:w-auto">
            {gmailStatus.connected ? (
              <div className="flex items-center gap-2 w-full md:w-auto justify-end">
                <button
                  onClick={() => loadMessages(pageToken)}
                  disabled={isLoadingEmails}
                  className="px-4 py-2.5 rounded-xl bg-white/10 hover:bg-white/15 text-white font-bold text-xs border border-white/15 flex items-center gap-2 transition disabled:opacity-50"
                  title="Refresh inbox"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isLoadingEmails ? 'animate-spin' : ''}`} />
                  <span>Sync Inbox</span>
                </button>
                <button
                  onClick={handleDisconnect}
                  disabled={isDisconnecting}
                  className="px-4 py-2.5 rounded-xl bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 border border-rose-500/40 font-bold text-xs flex items-center gap-1.5 transition disabled:opacity-50"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  <span>{isDisconnecting ? 'Disconnecting...' : 'Disconnect'}</span>
                </button>
              </div>
            ) : (
              <button
                onClick={handleConnectGmail}
                className="w-full sm:w-auto px-6 py-3 rounded-2xl bg-brand-yellow hover:bg-brand-yellowHover text-brand-darkText font-black text-sm shadow-glow-yellow flex items-center justify-center gap-2.5 transition active:scale-95"
              >
                {/* Google "G" Icon */}
                <svg className="w-4 h-4" viewBox="0 0 24 24">
                  <path
                    fill="currentColor"
                    d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                  />
                  <path
                    fill="currentColor"
                    d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                  />
                  <path
                    fill="currentColor"
                    d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                  />
                  <path
                    fill="currentColor"
                    d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                  />
                </svg>
                <span>{gmailStatus.scopeNeedsUpgrade ? 'Grant Gmail Access' : 'Connect Gmail'}</span>
                <ArrowRight className="w-4 h-4 ml-1" />
              </button>
            )}
          </div>
        </div>

        {/* Security Scope Notice */}
        <div className="mt-4 pt-4 border-t border-white/10 flex items-center justify-between flex-wrap gap-2 text-[11px] text-brand-cream/60">
          <div className="flex items-center gap-2">
            <Lock className="w-3.5 h-3.5 text-brand-yellow" />
            <span>Scope: <code className="text-white/80 font-mono">gmail.readonly</code> (Zero write permissions • No email deletion or outbound sending)</span>
          </div>
          <span>Client Secrets isolated to backend environment • Tokens protected in database</span>
        </div>
      </div>

      {/* Main Mailbox Interface: 2-Column Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column (5/12): Inbox Header, Search & Email List */}
        <div className="lg:col-span-5 glass-panel-purple p-5 rounded-[32px] border border-white/20 flex flex-col space-y-3.5 min-h-[620px]">
          {/* Header & Filter Pills */}
          <div className="flex items-center justify-between pb-2 border-b border-white/10">
            <div className="flex items-center gap-2">
              <Mail className="w-5 h-5 text-brand-yellow" />
              <h3 className="font-extrabold text-white text-base">
                Inbox ({filteredEmails.length})
              </h3>
            </div>
            <div className="flex items-center gap-1 bg-white/5 p-1 rounded-xl border border-white/10 text-[11px] overflow-x-auto no-scrollbar">
              <button
                onClick={() => handleFilterClick('ALL')}
                className={`px-2 py-0.5 rounded-lg font-bold transition flex-shrink-0 ${
                  activeFilter === 'ALL'
                    ? 'bg-brand-primary text-brand-yellow shadow-sm'
                    : 'text-white/70 hover:text-white'
                }`}
              >
                All
              </button>
              <button
                onClick={() => handleFilterClick('UNREAD')}
                className={`px-2 py-0.5 rounded-lg font-bold transition flex-shrink-0 ${
                  activeFilter === 'UNREAD'
                    ? 'bg-brand-primary text-brand-yellow shadow-sm'
                    : 'text-white/70 hover:text-white'
                }`}
              >
                Unread
              </button>
              <button
                onClick={() => handleFilterClick('NEEDS_REVIEW')}
                className={`px-2 py-0.5 rounded-lg font-bold transition flex-shrink-0 ${
                  activeFilter === 'NEEDS_REVIEW'
                    ? 'bg-brand-primary text-sky-300 shadow-sm'
                    : 'text-white/70 hover:text-white'
                }`}
              >
                Review
              </button>
              <button
                onClick={() => handleFilterClick('FLAGGED')}
                className={`px-2 py-0.5 rounded-lg font-bold transition flex-shrink-0 ${
                  activeFilter === 'FLAGGED'
                    ? 'bg-brand-primary text-rose-300 shadow-sm'
                    : 'text-white/70 hover:text-white'
                }`}
              >
                Threats
              </button>
              <button
                onClick={() => handleFilterClick('SPAM')}
                className={`px-2 py-0.5 rounded-lg font-bold transition flex-shrink-0 ${
                  activeFilter === 'SPAM'
                    ? 'bg-brand-primary text-amber-300 shadow-sm'
                    : 'text-white/70 hover:text-white'
                }`}
              >
                Spam
              </button>
            </div>
          </div>

          {/* Search Bar with Gmail Operators */}
          <form onSubmit={handleSearchSubmit} className="relative flex items-center">
            <Search className="w-4 h-4 text-brand-cream/50 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search sender, keywords, from:boss..."
              className="w-full bg-white/5 border border-white/10 rounded-2xl pl-10 pr-28 py-2.5 text-xs text-white placeholder-white/40 focus:outline-none focus:border-brand-lavender/60 transition"
            />
            <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1.5">
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => {
                    setSearchQuery('');
                    loadMessages(null, '');
                  }}
                  className="w-5 h-5 rounded-full bg-white/10 hover:bg-white/20 flex items-center justify-center text-white/60 hover:text-white transition"
                  title="Clear search"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
              <button
                type="submit"
                className="px-2.5 py-1 rounded-lg bg-brand-yellow/20 hover:bg-brand-yellow/30 text-brand-yellow text-[10px] font-bold transition flex items-center"
              >
                Search
              </button>
            </div>
          </form>

          {/* Emails Scroll List */}
          <div className="flex-1 space-y-2 overflow-y-auto max-h-[440px] pr-1">
            {isLoadingEmails ? (
              // Loading Skeletons
              Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="p-3.5 rounded-2xl bg-white/5 border border-white/5 animate-pulse space-y-2">
                  <div className="flex justify-between">
                    <div className="h-3 w-28 bg-white/20 rounded" />
                    <div className="h-2.5 w-16 bg-white/10 rounded" />
                  </div>
                  <div className="h-3 w-48 bg-white/15 rounded" />
                  <div className="h-2 w-full bg-white/10 rounded" />
                </div>
              ))
            ) : filteredEmails.length === 0 ? (
              <div className="text-center py-12 text-brand-cream/60 space-y-2">
                <Mail className="w-8 h-8 mx-auto text-white/20" />
                <p className="text-xs">No emails match your filter or search query.</p>
                {searchQuery && (
                  <button
                    onClick={() => {
                      setSearchQuery('');
                      loadMessages(null, '');
                    }}
                    className="text-xs text-brand-yellow underline"
                  >
                    Clear search filter
                  </button>
                )}
              </div>
            ) : (
              filteredEmails.map((e) => {
                const isSelected = selectedEmail?.id === e.id;
                return (
                  <div
                    key={e.id}
                    onClick={() => handleSelectEmail(e.id)}
                    className={`p-3.5 rounded-2xl cursor-pointer transition border text-left relative ${
                      isSelected
                        ? 'bg-brand-primary/60 border-brand-lavender shadow-md shadow-brand-primary/20'
                        : 'bg-white/5 border-white/5 hover:bg-white/10'
                    }`}
                  >
                    {/* Unread dot */}
                    {!e.isRead && (
                      <span className="absolute left-1.5 top-1/2 -translate-y-1/2 w-1.5 h-1.5 rounded-full bg-brand-yellow shadow-glow-yellow" />
                    )}

                    <div className="flex items-center justify-between mb-1 pl-1.5">
                      <div className="flex items-center gap-1.5 truncate max-w-[190px]">
                        <span className={`text-xs truncate ${!e.isRead ? 'font-black text-white' : 'font-semibold text-brand-cream/90'}`}>
                          {e.senderName}
                        </span>
                        {e.isSpam && (
                          <span className="text-[8px] font-black px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                            SPAM
                          </span>
                        )}
                      </div>
                      <span className="text-[10px] text-brand-cream/60 flex-shrink-0">{e.date}</span>
                    </div>

                    <div className={`text-xs truncate mb-1 pl-1.5 ${!e.isRead ? 'font-bold text-white' : 'text-brand-cream/80'}`}>
                      {e.subject || '(No Subject)'}
                    </div>

                    <div className="flex items-center justify-between pl-1.5">
                      <span className="text-[11px] text-white/50 truncate max-w-[190px]">
                        {e.snippet || e.preview || '(Empty message preview)'}
                      </span>

                      {e.securityStatus === 'THREAT_INTERCEPTED' || e.securityStatus === 'PROMPT_INJECTION_BLOCKED' ? (
                        <span className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/40 flex-shrink-0">
                          Threat Intercepted
                        </span>
                      ) : e.securityStatus === 'SUSPICIOUS' ? (
                        <span className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 flex-shrink-0">
                          Suspicious
                        </span>
                      ) : e.securityStatus === 'NEEDS_REVIEW' ? (
                        <span className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-sky-500/20 text-sky-300 border border-sky-500/40 flex-shrink-0">
                          Needs Review
                        </span>
                      ) : (
                        <span className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 flex-shrink-0">
                          Verified Safe
                        </span>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Pagination Controls */}
          {gmailStatus.connected && (
            <div className="pt-3 border-t border-white/10 flex items-center justify-between text-xs text-brand-cream/70">
              <span className="text-[11px]">Page {pageNumber}</span>
              <div className="flex items-center gap-1.5">
                <button
                  onClick={handlePrevPage}
                  disabled={tokenStack.length === 0 || isLoadingEmails}
                  className="px-2.5 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-white disabled:opacity-30 disabled:pointer-events-none flex items-center gap-1 text-[11px]"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                  <span>Previous</span>
                </button>
                <button
                  onClick={handleNextPage}
                  disabled={!nextPageToken || isLoadingEmails}
                  className="px-2.5 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-white disabled:opacity-30 disabled:pointer-events-none flex items-center gap-1 text-[11px]"
                >
                  <span>Next</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Right Column (7/12): Email Reader & Butler Security Inspector */}
        <div className="lg:col-span-7 glass-panel-purple p-6 rounded-[32px] border border-white/20 flex flex-col space-y-5 min-h-[620px]">
          {isLoadingDetail ? (
            <div className="flex-1 flex flex-col items-center justify-center space-y-3 py-20">
              <RefreshCw className="w-8 h-8 text-brand-yellow animate-spin" />
              <p className="text-xs text-brand-cream/70 font-semibold">
                Fetching message contents & running Zero-Trust security scan...
              </p>
            </div>
          ) : emailDetail ? (
            <>
              {/* Header Details */}
              <div className="pb-4 border-b border-white/10 space-y-3">
                <div className="flex items-start justify-between gap-4">
                  <h3 className="text-lg sm:text-xl font-black text-white leading-snug">
                    {emailDetail.subject || '(No Subject)'}
                  </h3>
                  <button
                    onClick={handleAnalyzeWithButler}
                    disabled={analyzingEmail}
                    className="px-4 py-2 rounded-xl bg-brand-yellow hover:bg-brand-yellowHover text-brand-darkText font-bold text-xs shadow-glow-yellow flex items-center gap-1.5 transition disabled:opacity-40 flex-shrink-0"
                  >
                    {analyzingEmail ? (
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Shield className="w-3.5 h-3.5" />
                    )}
                    <span>Analyze with Butler</span>
                  </button>
                </div>

                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-brand-cream/70">
                  <div className="space-y-1">
                    <div>
                      From: <strong className="text-white">{emailDetail.senderName}</strong>{' '}
                      <span className="text-white/60">&lt;{emailDetail.from}&gt;</span>
                    </div>
                    {emailDetail.to && (
                      <div className="text-[11px] text-white/50">
                        To: {emailDetail.to}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5 text-[11px] text-white/60 self-start sm:self-auto">
                    <Clock className="w-3 h-3 text-brand-yellow" />
                    <span>{emailDetail.date}</span>
                  </div>
                </div>

                {/* Attachments Section */}
                {emailDetail.attachments && emailDetail.attachments.length > 0 && (
                  <div className="pt-2 flex flex-wrap gap-2">
                    {emailDetail.attachments.map((att, idx) => (
                      <div
                        key={idx}
                        className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-white/5 border border-white/10 text-xs text-brand-cream"
                      >
                        <Paperclip className="w-3.5 h-3.5 text-brand-yellow" />
                        <span className="font-semibold text-white">{att.filename}</span>
                        <span className="text-[10px] text-white/50">
                          ({Math.round((att.size || 0) / 1024)} KB)
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {/* Spam Quarantine Notice */}
                {emailDetail.isSpam && (
                  <div className="p-3 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-center gap-2.5 text-xs text-amber-200">
                    <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />
                    <span>
                      <strong>Gmail Native Spam:</strong> Google quarantined this email in your Spam folder. Verified and neutralized by Butler Guard.
                    </span>
                  </div>
                )}
              </div>

              {/* View Toggle: Formatted Sanitized HTML vs Plain Text */}
              <div className="flex items-center justify-between text-xs">
                <span className="text-[11px] text-brand-cream/60 font-semibold uppercase tracking-wider">
                  Email Content (Sanitized)
                </span>
                <div className="flex items-center gap-1 bg-white/5 p-1 rounded-xl border border-white/10 text-[11px]">
                  <button
                    onClick={() => setViewMode('html')}
                    className={`px-2.5 py-0.5 rounded-lg font-bold transition ${
                      viewMode === 'html'
                        ? 'bg-brand-primary text-brand-yellow shadow-sm'
                        : 'text-white/70 hover:text-white'
                    }`}
                  >
                    HTML
                  </button>
                  <button
                    onClick={() => setViewMode('text')}
                    className={`px-2.5 py-0.5 rounded-lg font-bold transition ${
                      viewMode === 'text'
                        ? 'bg-brand-primary text-brand-yellow shadow-sm'
                        : 'text-white/70 hover:text-white'
                    }`}
                  >
                    Plain Text
                  </button>
                </div>
              </div>

              {/* Email Content Body Container */}
              <div className="flex-1 p-5 rounded-2xl bg-black/40 border border-white/10 text-xs sm:text-sm text-brand-cream font-sans leading-relaxed max-h-[300px] overflow-y-auto">
                {viewMode === 'html' && emailDetail.bodyHtml ? (
                  <div
                    className="prose prose-invert max-w-none text-xs sm:text-sm"
                    dangerouslySetInnerHTML={{
                      __html: DOMPurify.sanitize(emailDetail.bodyHtml, {
                        USE_PROFILES: { html: true }
                      })
                    }}
                  />
                ) : (
                  <pre className="whitespace-pre-wrap font-sans text-xs sm:text-sm text-brand-cream/90">
                    {emailDetail.bodyText || emailDetail.body || emailDetail.snippet || '(No message body)'}
                  </pre>
                )}
              </div>

              {/* Butler Security Analysis Banner */}
              {analysisReport && (
                <div
                  className={`p-4 rounded-2xl border transition ${
                    (analysisReport.riskScore ?? 0) >= 75
                      ? 'bg-rose-950/40 border-rose-500/40'
                      : (analysisReport.riskScore ?? 0) >= 50
                      ? 'bg-amber-950/40 border-amber-500/40'
                      : (analysisReport.riskScore ?? 0) >= 20
                      ? 'bg-sky-950/40 border-sky-500/40'
                      : 'bg-emerald-950/40 border-emerald-500/40'
                  } space-y-2`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 font-black text-sm text-white">
                      {(analysisReport.riskScore ?? 0) >= 75 ? (
                        <AlertOctagon className="w-5 h-5 text-rose-400" />
                      ) : (analysisReport.riskScore ?? 0) >= 50 ? (
                        <AlertTriangle className="w-5 h-5 text-amber-400" />
                      ) : (analysisReport.riskScore ?? 0) >= 20 ? (
                        <Eye className="w-5 h-5 text-sky-400" />
                      ) : (
                        <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                      )}
                      <span>
                        {(analysisReport.riskScore ?? 0) >= 75
                          ? `Threat Intercepted by Butler (Risk Score: ${analysisReport.riskScore ?? 0}/100)`
                          : (analysisReport.riskScore ?? 0) >= 50
                          ? `Suspicious Email Detected (Risk Score: ${analysisReport.riskScore ?? 0}/100)`
                          : (analysisReport.riskScore ?? 0) >= 20
                          ? `Email Needs Review (Risk Score: ${analysisReport.riskScore ?? 0}/100)`
                          : `Email Verified Clean & Safe (Risk Score: ${analysisReport.riskScore ?? 0}/100)`}
                      </span>
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-white/10 font-mono text-white/80">
                      Layer 1-4 Zero-Trust Guard
                    </span>
                  </div>

                  {/* Auth signals & Domain Badges */}
                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    {analysisReport.isKnownTrustedDomain && (
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-md bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
                        <Check className="w-3 h-3" /> Verified Domain (@{analysisReport.senderDomain})
                      </span>
                    )}
                    {analysisReport.authSignals?.spf === 'pass' && (
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-md bg-white/10 text-brand-cream border border-white/15">
                        SPF: Pass
                      </span>
                    )}
                    {analysisReport.authSignals?.dkim === 'pass' && (
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-md bg-white/10 text-brand-cream border border-white/15">
                        DKIM: Pass
                      </span>
                    )}
                    {analysisReport.threats && analysisReport.threats.length > 0 && analysisReport.threats.map((t, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded-lg bg-rose-500/20 text-rose-300 text-[10px] font-bold border border-rose-500/30"
                      >
                        {t.name || t.category || t}
                      </span>
                    ))}
                  </div>

                  {/* Explanation & Evidence */}
                  <p className="text-xs text-brand-cream/90 font-sans leading-relaxed pt-1">
                    {analysisReport.explanation || analysisReport.analysisSummary || 'Inspected under AI Action Firewall.'}
                  </p>

                  {analysisReport.evidence && analysisReport.evidence.length > 0 && (
                    <div className="mt-2 p-2.5 rounded-xl bg-black/40 border border-white/10 space-y-1">
                      <div className="text-[10px] font-bold uppercase tracking-wider text-brand-cream/60">
                        Security Verification Findings
                      </div>
                      {analysisReport.evidence.map((ev, i) => (
                        <div key={i} className="text-[11px] text-white/80 font-mono flex items-start gap-1.5">
                          <span className="text-brand-yellow">•</span>
                          <span>{ev}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-center py-20 text-brand-cream/60 space-y-3">
              <Mail className="w-12 h-12 text-white/20" />
              <div className="font-bold text-white text-base">Select an email to inspect</div>
              <p className="text-xs max-w-sm text-brand-cream/60">
                Choose an email from the left column to read its content, review attachments, and execute real-time Butler security analysis.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

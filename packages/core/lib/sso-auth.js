/**
 * SSO/SAML Authentication System
 * 
 * Enterprise single sign-on support for CodeTitan.
 * Implements SAML 2.0 and OAuth 2.0/OIDC for enterprise customers.
 * 
 * @module sso-auth
 */

/**
 * SSO Provider Configuration
 */
const SSO_PROVIDERS = {
    // SAML 2.0 Providers
    OKTA: {
        type: 'SAML',
        name: 'Okta',
        description: 'Okta SSO via SAML 2.0',
        configFields: ['entityId', 'ssoUrl', 'certificate', 'signRequest'],
    },
    AZURE_AD: {
        type: 'SAML',
        name: 'Azure Active Directory',
        description: 'Microsoft Azure AD via SAML 2.0',
        configFields: ['entityId', 'ssoUrl', 'certificate', 'tenantId'],
    },
    ONELOGIN: {
        type: 'SAML',
        name: 'OneLogin',
        description: 'OneLogin SSO via SAML 2.0',
        configFields: ['entityId', 'ssoUrl', 'certificate'],
    },
    GOOGLE_WORKSPACE: {
        type: 'SAML',
        name: 'Google Workspace',
        description: 'Google Workspace SSO via SAML 2.0',
        configFields: ['entityId', 'ssoUrl', 'certificate'],
    },

    // OAuth 2.0/OIDC Providers
    GITHUB: {
        type: 'OAUTH',
        name: 'GitHub',
        description: 'GitHub OAuth 2.0',
        configFields: ['clientId', 'clientSecret', 'allowedOrgs'],
        authUrl: 'https://github.com/login/oauth/authorize',
        tokenUrl: 'https://github.com/login/oauth/access_token',
        scopes: ['read:user', 'user:email', 'read:org'],
    },
    GOOGLE: {
        type: 'OIDC',
        name: 'Google',
        description: 'Google OAuth 2.0 / OIDC',
        configFields: ['clientId', 'clientSecret', 'hostedDomain'],
        authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
        tokenUrl: 'https://oauth2.googleapis.com/token',
        scopes: ['openid', 'email', 'profile'],
    },
    MICROSOFT: {
        type: 'OIDC',
        name: 'Microsoft',
        description: 'Microsoft OAuth 2.0 / OIDC',
        configFields: ['clientId', 'clientSecret', 'tenantId'],
        authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        scopes: ['openid', 'email', 'profile'],
    },
};

/**
 * SAML Configuration class
 */
class SAMLConfig {
    constructor(options) {
        this.entityId = options.entityId;  // IdP Entity ID
        this.ssoUrl = options.ssoUrl;  // IdP SSO URL
        this.certificate = options.certificate;  // IdP Certificate
        this.signRequest = options.signRequest ?? true;
        this.signatureAlgorithm = options.signatureAlgorithm ?? 'sha256';
        this.callbackUrl = options.callbackUrl;  // Our ACS URL
        this.issuer = options.issuer ?? 'codetitan';  // Our Entity ID
        this.wantAssertionsSigned = options.wantAssertionsSigned ?? true;
        this.validateInResponseTo = options.validateInResponseTo ?? true;
    }

    toJSON() {
        return {
            entityId: this.entityId,
            ssoUrl: this.ssoUrl,
            callbackUrl: this.callbackUrl,
            issuer: this.issuer,
            signRequest: this.signRequest,
        };
    }
}

/**
 * OAuth Configuration class
 */
class OAuthConfig {
    constructor(options) {
        this.clientId = options.clientId;
        this.clientSecret = options.clientSecret;
        this.authUrl = options.authUrl;
        this.tokenUrl = options.tokenUrl;
        this.scopes = options.scopes ?? [];
        this.callbackUrl = options.callbackUrl;
        this.state = options.state;
        this.allowedDomains = options.allowedDomains ?? [];
        this.allowedOrgs = options.allowedOrgs ?? [];
    }

    getAuthorizationUrl() {
        const params = new URLSearchParams({
            client_id: this.clientId,
            redirect_uri: this.callbackUrl,
            response_type: 'code',
            scope: this.scopes.join(' '),
            state: this.state,
        });
        return `${this.authUrl}?${params.toString()}`;
    }

    toJSON() {
        return {
            clientId: this.clientId,
            authUrl: this.authUrl,
            callbackUrl: this.callbackUrl,
            scopes: this.scopes,
        };
    }
}

/**
 * SSO Session
 */
class SSOSession {
    constructor(options) {
        this.userId = options.userId;
        this.email = options.email;
        this.name = options.name;
        this.provider = options.provider;
        this.providerId = options.providerId;  // ID from the provider
        this.roles = options.roles ?? [];
        this.groups = options.groups ?? [];
        this.createdAt = new Date();
        this.expiresAt = options.expiresAt ?? new Date(Date.now() + 8 * 60 * 60 * 1000);  // 8 hours
        this.metadata = options.metadata ?? {};
    }

    isExpired() {
        return new Date() > this.expiresAt;
    }

    hasRole(role) {
        return this.roles.includes(role);
    }

    hasGroup(group) {
        return this.groups.includes(group);
    }

    toJSON() {
        return {
            userId: this.userId,
            email: this.email,
            name: this.name,
            provider: this.provider,
            roles: this.roles,
            groups: this.groups,
            createdAt: this.createdAt.toISOString(),
            expiresAt: this.expiresAt.toISOString(),
        };
    }
}

/**
 * SSO Authentication Manager
 */
class SSOManager {
    constructor(options = {}) {
        this.configs = new Map();  // provider -> config
        this.sessions = new Map();  // sessionId -> SSOSession
        this.baseUrl = options.baseUrl ?? 'https://codetitan.dev';
        this.sessionDuration = options.sessionDuration ?? 8 * 60 * 60 * 1000;  // 8 hours
    }

    /**
     * Configure a SAML provider
     */
    configureSAML(providerId, options) {
        const provider = SSO_PROVIDERS[providerId];
        if (!provider || provider.type !== 'SAML') {
            throw new Error(`Unknown SAML provider: ${providerId}`);
        }

        const config = new SAMLConfig({
            ...options,
            callbackUrl: `${this.baseUrl}/api/auth/saml/callback`,
        });

        this.configs.set(providerId, { type: 'SAML', config, provider });
        return config;
    }

    /**
     * Configure an OAuth provider
     */
    configureOAuth(providerId, options) {
        const provider = SSO_PROVIDERS[providerId];
        if (!provider || !['OAUTH', 'OIDC'].includes(provider.type)) {
            throw new Error(`Unknown OAuth provider: ${providerId}`);
        }

        const config = new OAuthConfig({
            ...options,
            authUrl: provider.authUrl,
            tokenUrl: provider.tokenUrl,
            scopes: provider.scopes,
            callbackUrl: `${this.baseUrl}/api/auth/oauth/callback`,
        });

        this.configs.set(providerId, { type: 'OAUTH', config, provider });
        return config;
    }

    /**
     * Get SSO login URL for a provider
     */
    getLoginUrl(providerId, state) {
        const entry = this.configs.get(providerId);
        if (!entry) {
            throw new Error(`Provider not configured: ${providerId}`);
        }

        if (entry.type === 'SAML') {
            // Generate SAML AuthnRequest URL
            return this.generateSAMLAuthnRequest(entry.config, state);
        } else {
            // Generate OAuth authorization URL
            entry.config.state = state;
            return entry.config.getAuthorizationUrl();
        }
    }

    /**
     * Generate SAML AuthnRequest
     */
    generateSAMLAuthnRequest(config, state) {
        // In production, use a proper SAML library like passport-saml or saml2-js
        // This is a simplified implementation for demonstration
        const requestId = `_${this.generateId()}`;
        const issueInstant = new Date().toISOString();

        const authnRequest = `
            <samlp:AuthnRequest
                xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="${requestId}"
                Version="2.0"
                IssueInstant="${issueInstant}"
                Destination="${config.ssoUrl}"
                AssertionConsumerServiceURL="${config.callbackUrl}"
            >
                <saml:Issuer>${config.issuer}</saml:Issuer>
            </samlp:AuthnRequest>
        `;

        // Base64 encode and URL encode
        const encoded = Buffer.from(authnRequest).toString('base64');
        const params = new URLSearchParams({
            SAMLRequest: encoded,
            RelayState: state,
        });

        return `${config.ssoUrl}?${params.toString()}`;
    }

    /**
     * Process SAML response
     */
    processSAMLResponse(samlResponse, relayState) {
        // In production, use a proper SAML library to verify and parse
        // This is a simplified implementation
        const decoded = Buffer.from(samlResponse, 'base64').toString('utf-8');

        // Extract user info (simplified - real impl would parse XML properly)
        const emailMatch = decoded.match(/<saml:NameID[^>]*>([^<]+)<\/saml:NameID>/);
        const email = emailMatch ? emailMatch[1] : null;

        if (!email) {
            throw new Error('Could not extract user email from SAML response');
        }

        return this.createSession({
            email,
            name: email.split('@')[0],
            provider: 'SAML',
            providerId: email,
            metadata: { relayState },
        });
    }

    /**
     * Exchange OAuth code for tokens
     */
    async exchangeOAuthCode(providerId, code) {
        const entry = this.configs.get(providerId);
        if (!entry) {
            throw new Error(`Provider not configured: ${providerId}`);
        }

        // In production, make actual HTTP request to token endpoint
        // This is a placeholder that would be replaced with actual token exchange
        const tokenResponse = {
            access_token: 'mock_access_token',
            token_type: 'Bearer',
            expires_in: 3600,
            refresh_token: 'mock_refresh_token',
        };

        return tokenResponse;
    }

    /**
     * Get user info from OAuth provider
     */
    async getOAuthUserInfo(providerId, accessToken) {
        // In production, fetch user info from provider's API
        // This is a placeholder
        return {
            email: 'user@example.com',
            name: 'Example User',
            providerId: 'user123',
        };
    }

    /**
     * Create SSO session
     */
    createSession(options) {
        const sessionId = this.generateId();
        const session = new SSOSession({
            ...options,
            userId: this.generateId(),
            expiresAt: new Date(Date.now() + this.sessionDuration),
        });

        this.sessions.set(sessionId, session);

        return {
            sessionId,
            session: session.toJSON(),
        };
    }

    /**
     * Validate session
     */
    validateSession(sessionId) {
        const session = this.sessions.get(sessionId);

        if (!session) {
            return { valid: false, error: 'Session not found' };
        }

        if (session.isExpired()) {
            this.sessions.delete(sessionId);
            return { valid: false, error: 'Session expired' };
        }

        return { valid: true, session: session.toJSON() };
    }

    /**
     * Logout and invalidate session
     */
    logout(sessionId) {
        const existed = this.sessions.has(sessionId);
        this.sessions.delete(sessionId);
        return existed;
    }

    /**
     * Get available providers
     */
    getAvailableProviders() {
        return Object.entries(SSO_PROVIDERS).map(([id, provider]) => ({
            id,
            name: provider.name,
            type: provider.type,
            description: provider.description,
            configured: this.configs.has(id),
        }));
    }

    /**
     * Generate random ID
     */
    generateId() {
        return 'id_' + Math.random().toString(36).substring(2, 15) +
            Math.random().toString(36).substring(2, 15);
    }
}

/**
 * Role-Based Access Control
 */
const RBAC_ROLES = {
    ADMIN: {
        name: 'Administrator',
        permissions: ['*'],  // All permissions
    },
    OWNER: {
        name: 'Owner',
        permissions: [
            'project:*',
            'team:*',
            'billing:*',
            'settings:*',
        ],
    },
    MANAGER: {
        name: 'Manager',
        permissions: [
            'project:read',
            'project:create',
            'project:update',
            'team:read',
            'team:invite',
            'analysis:*',
        ],
    },
    DEVELOPER: {
        name: 'Developer',
        permissions: [
            'project:read',
            'analysis:run',
            'analysis:read',
            'fix:apply',
        ],
    },
    VIEWER: {
        name: 'Viewer',
        permissions: [
            'project:read',
            'analysis:read',
        ],
    },
};

/**
 * Check if a role has a specific permission
 */
function hasPermission(role, permission) {
    const roleConfig = RBAC_ROLES[role];
    if (!roleConfig) return false;

    // Check for wildcard permissions
    if (roleConfig.permissions.includes('*')) return true;

    // Check for category wildcard (e.g., 'project:*' for 'project:read')
    const [category, action] = permission.split(':');
    if (roleConfig.permissions.includes(`${category}:*`)) return true;

    // Check for exact permission
    return roleConfig.permissions.includes(permission);
}

module.exports = {
    SSOManager,
    SAMLConfig,
    OAuthConfig,
    SSOSession,
    SSO_PROVIDERS,
    RBAC_ROLES,
    hasPermission,
};

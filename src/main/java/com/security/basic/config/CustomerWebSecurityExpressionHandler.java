package com.security.basic.config;

import org.springframework.security.access.expression.AbstractSecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;

public class CustomerWebSecurityExpressionHandler extends AbstractSecurityExpressionHandler<FilterInvocation> {
    private final AuthenticationTrustResolver trustResolver;

    private final String defaultRolePrefix;

    public CustomerWebSecurityExpressionHandler(AuthenticationTrustResolver trustResolver, String defaultRolePrefix) {
        this.trustResolver = trustResolver;
        this.defaultRolePrefix = defaultRolePrefix;
    }

    @Override
    protected SecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication, FilterInvocation invocation) {
        CustomWebSecurityExpressionRoot root = new CustomWebSecurityExpressionRoot(authentication, invocation);
        root.setPermissionEvaluator(getPermissionEvaluator());
        root.setTrustResolver(this.trustResolver);
        root.setRoleHierarchy(getRoleHierarchy());
        root.setDefaultRolePrefix(this.defaultRolePrefix);
        return root;
    }
}
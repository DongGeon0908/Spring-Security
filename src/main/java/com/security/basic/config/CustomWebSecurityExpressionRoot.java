package com.security.basic.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CustomWebSecurityExpressionRoot extends WebSecurityExpressionRoot {

    static final Pattern pattern = Pattern.compile("[0-9]+$");

    public CustomWebSecurityExpressionRoot(Authentication a, FilterInvocation fi) {
        super(a, fi);
    }

    public boolean isOddAdmin() {
        User user = (User) getAuthentication().getPrincipal();
        String name = user.getUsername();
        Matcher matcher = pattern.matcher(name);
        if (matcher.find()) {
            int number = Integer.parseInt(matcher.group(0));
            return number % 2 == 1;
        }
        return false;
    }
}

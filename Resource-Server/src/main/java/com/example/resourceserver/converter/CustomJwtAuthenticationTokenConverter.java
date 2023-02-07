package com.example.resourceserver.converter;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.List;

public class CustomJwtAuthenticationTokenConverter implements Converter<Jwt, JwtAuthenticationToken> {


    @Override
    public JwtAuthenticationToken convert(Jwt source) {
       //mi cemo da dobijemo stringove authorities a mormao da ih mapiramo u SimpleGrantedAuthoritiy
        List<String> authorityList=source.getClaimAsStringList("authorities");

        JwtAuthenticationToken authenticationToken=new JwtAuthenticationToken(source,authorityList.stream().map(SimpleGrantedAuthority::new).toList());

        return authenticationToken ;
    }


}

package br.ufg.twssl.config;

import br.ufg.twssl.service.CertificateService;
import br.ufg.twssl.service.JwtService;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

@Configuration
@AllArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    final static String AUTHCONST="Authorization";
    final static String BEARERCONST="Bearer ";


    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String username;
        if(Objects.nonNull(request.getHeader(AUTHCONST)) || !request.getHeader(AUTHCONST).startsWith(BEARERCONST)){
            filterChain.doFilter(request,response);
        }else{
            final String jwt = request.getHeader(AUTHCONST).substring(BEARERCONST.length());
            username = this.jwtService.extractUsername(jwt);
            if(Objects.nonNull(username) && Objects.nonNull(SecurityContextHolder.getContext().getAuthentication())){
                final UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                if (jwtService.isTokenValid(jwt,userDetails)){
                    final UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }else{
                    filterChain.doFilter(request,response);
                    throw new UsernameNotFoundException("Token inválido");
                }
            } else{
                filterChain.doFilter(request,response);
                throw new UsernameNotFoundException("Usuário informado incorreto");
            }
        }
        filterChain.doFilter(request,response);
    }
}

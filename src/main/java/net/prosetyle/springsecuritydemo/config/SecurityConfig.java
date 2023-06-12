package net.prosetyle.springsecuritydemo.config;

import net.prosetyle.springsecuritydemo.model.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        return new InMemoryUserDetailsManager(
                User.builder()
                        .username("admin")
                        .password(passwordEncoder.encode("admin"))
                        .authorities(Role.ADMIN.getAuthorities())
                        .build(),
                User.builder()
                        .username("user")
                        .password(passwordEncoder.encode("user"))
                        .authorities(Role.USER.getAuthorities())
                        .build()
        );
    }

    @Bean
    protected PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http)  throws Exception{
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(
                        auth -> auth
                                .requestMatchers("/").permitAll() // в корень проекта - доступ кто угодно
                                //.requestMatchers(HttpMethod.GET, "api/**").hasAuthority(Permission.DEVELOPERS_READ.getPermission())
                                //.requestMatchers(HttpMethod.POST, "api/**").hasAuthority(Permission.DEVELOPERS_WRITE.getPermission())
                                //.requestMatchers(HttpMethod.DELETE, "api/**").hasAuthority(Permission.DEVELOPERS_WRITE.getPermission())
                                .anyRequest()   //каждый запрос
                                .authenticated()
                        //должен быть аутентифицирован
                )
                //.httpBasic(Customizer.withDefaults())
                .formLogin(login -> login
                        .loginPage("/auth/login").permitAll()
                        .defaultSuccessUrl("/auth/success")
                )
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/auth/logout", "POST"))
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID")
                        .logoutSuccessUrl("/auth/login"))
                .build();
    }
}

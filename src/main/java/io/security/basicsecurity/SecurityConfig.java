package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity //웹 보안 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS","USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN","SYS","USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

//        http.csrf(); thymeleaf 또는 spring form 을 사용할때는 기본적으로 csrf 를 생성해서 보내준다.
        //인가 정책
        // * 주의 사항 - 설정 시 구체적인 경로가 먼저 오고 그것 보다 큰 범위의 경로가 뒤에 오도록 해야한다.
        http
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();
        //인증 정책
        http.formLogin();
//                .successHandler((request, response, authentication) -> {
//                    RequestCache requestCache = new HttpSessionRequestCache();
//                    SavedRequest savedRequest = requestCache.getRequest(request, response);
//                    String redirectUrl = savedRequest.getRedirectUrl();
//                    response.sendRedirect(redirectUrl);
//                });
//
//        http
//                .exceptionHandling()
//                .authenticationEntryPoint((request, response, authException) -> response.sendRedirect("/login")) // 인증 에러 해들러
//                .accessDeniedHandler((request, response, accessDeniedException) -> response.sendRedirect("/denied")); // 인가 에러 핸들러


//                .loginPage("/loginPage")
//                .defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                .loginProcessingUrl("/login_proc")
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        System.out.println("a = " + authentication.getName());
//                        response.sendRedirect("/");
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("exception = " + exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                }).permitAll();
////                .loginPage("/login.html") // 사용자 정의 로그인 페이지
////                .defaultSuccessUrl("/home") // 로그인 성공 후 이동 페이지
////                .failureUrl("/login.html?error=true") // 로그인 실패 후 이동 페이지
////                .usernameParameter("username") //아이디 파라미터명 설정
////                .passwordParameter("password") //패스워드 파라미터명 설정
////                .loginProcessingUrl("/login") // 로그인 Form Action Url
////                .successHandler(loginSuccessHandler()) //로그인 성공후 핸들러
////                .failureHandler(loginFailureHandler()) //로그인 실패후 핸들러
//
//
//        http.logout()
//                .logoutUrl("/logout")
//                .logoutSuccessUrl("/login")
//                .addLogoutHandler((request, response, authentication) -> {
//                    HttpSession session = request.getSession();
//                    session.invalidate();
//                })
//                .logoutSuccessHandler((request, response, authentication) -> response.sendRedirect("/login"))
//                .deleteCookies("remember-me");
//
////                .logoutUrl("/logout") // 로그아웃 처리 URL
////                .logoutSuccessUrl("/login") //로그아웃 성공 후 이동 페이지
////                .deleteCookies("JSESSIONID", "remember-me") // 로그아웃 쿠키 삭제
////                .addLogoutHandler(logoutHandler()) //로그아웃 핸들러
////                .logoutSuccessHandler(logoutSuccessHandler()); // 로그아웃 성공후 핸들러
//
//
//        http.rememberMe()
//                .rememberMeParameter("remember") // 기본 파라미터명은 remember-me
//                .tokenValiditySeconds(3600) // default 는 14 일
//                .alwaysRemember(true) //리멤버 미 기능이 활성화되지 않아도 항상 실행
//                .userDetailsService(userDetailsService);
//
//
//        http.sessionManagement()
////                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS) // 스프링 시큐리티가 항상 세션 생성
////                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 스프링 시큐리티가 필요시 생성(기본값)
////                .sessionCreationPolicy(SessionCreationPolicy.NEVER) // 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
////                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 스프링 시큐리티가 생성하지 않고 존재해도 사용하지않음 (JWT 사용할떄)
//                .sessionFixation().changeSessionId() //세션 고정 보호 세션을 로그인 할때마다 바꿔서 줌 (default)
//                .maximumSessions(1) // 최대 허용가능 세션수 , -1: 무제한 로그인 세션 허용
//                .maxSessionsPreventsLogin(false) //동시 로그인 차단함, false: 기존 세션 만료 (default)
////                .invalidSessionUrl("/invalid") // 세션이 유효하지 않을때 이동 할 페이지 1 먼저실행
//                .expiredUrl("/expired");// 세션이 만료된 경우 이동 할 페이지 2
//
//

    }
}

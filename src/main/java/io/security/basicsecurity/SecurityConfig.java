package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity //웹 보안 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //인가 정책
        http
                .authorizeRequests()
                .anyRequest().authenticated();
        //인증 정책
        http.formLogin()
//                .loginPage("/loginPage")
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("a = " + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception = " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                }).permitAll();
//                .loginPage("/login.html") // 사용자 정의 로그인 페이지
//                .defaultSuccessUrl("/home") // 로그인 성공 후 이동 페이지
//                .failureUrl("/login.html?error=true") // 로그인 실패 후 이동 페이지
//                .usernameParameter("username") //아이디 파라미터명 설정
//                .passwordParameter("password") //패스워드 파라미터명 설정
//                .loginProcessingUrl("/login") // 로그인 Form Action Url
//                .successHandler(loginSuccessHandler()) //로그인 성공후 핸들러
//                .failureHandler(loginFailureHandler()) //로그인 실패후 핸들러


        http.logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .addLogoutHandler((request, response, authentication) -> {
                    HttpSession session = request.getSession();
                    session.invalidate();
                })
                .logoutSuccessHandler((request, response, authentication) -> response.sendRedirect("/login"))
                .deleteCookies("remember-me");

//                .logoutUrl("/logout") // 로그아웃 처리 URL
//                .logoutSuccessUrl("/login") //로그아웃 성공 후 이동 페이지
//                .deleteCookies("JSESSIONID", "remember-me") // 로그아웃 쿠키 삭제
//                .addLogoutHandler(logoutHandler()) //로그아웃 핸들러
//                .logoutSuccessHandler(logoutSuccessHandler()); // 로그아웃 성공후 핸들러

    }
}

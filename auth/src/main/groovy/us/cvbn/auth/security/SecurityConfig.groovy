package us.cvbn.auth.security


import org.springframework.context.annotation.Configuration
import org.springframework.beans.factory.BeanCreationException
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.web.filter.ForwardedHeaderFilter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // @Autowired
    // private PortalWebSecurityHelper portalWebSecurityHelper

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // http.authorizeRequests()
        // .antMatchers("/oauth_login")
        // .permitAll()
        // .anyRequest()
        // .authenticated()
        // .and()
        // .oauth2Login()
        // .loginPage("/oauth_login");

        http.httpBasic()
			  .and()
			    .csrf().disable()
			    .authorizeRequests()
			        .anyRequest()
			            .authenticated().and().oauth2Login();
    }


    @Bean
	FilterRegistrationBean<ForwardedHeaderFilter> forwardedHeaderFilter() {
		
	    final FilterRegistrationBean<ForwardedHeaderFilter> filterRegistrationBean = new FilterRegistrationBean<ForwardedHeaderFilter>();
	    
	    filterRegistrationBean.setFilter(new ForwardedHeaderFilter());
	    filterRegistrationBean.setOrder(Ordered.HIGHEST_PRECEDENCE);
	    
	    return filterRegistrationBean;
	}
}
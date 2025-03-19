package home.spring.security.springsecurity;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class SpringSecurityConfig {
	
	@Bean
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
            .setType(EmbeddedDatabaseType.H2)
            .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
            .build();
    }
	
	@Bean
	public UserDetailsManager user(DataSource dataSource) {
//		
//		UserDetails user1 = User.withDefaultPasswordEncoder()
//				.username("chayan1")
//				.password("1234")
//				.roles("ADMIN")
//				.build();
//		UserDetails user2 = User.withDefaultPasswordEncoder()
//				.username("chayan2")
//				.password("1234")
//				.roles("USER")
//				.build();
		
		
		JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
//		jdbcUserDetailsManager.createUser(user1);
//		jdbcUserDetailsManager.createUser(user2);
		
		jdbcUserDetailsManager.setUsersByUsernameQuery("select username, password, enabled from users where username = ?");
		
//		jdbcUserDetailsManager.loadUserByUsername(userName);
//		jdbcUserDetailsManager.auth
		
		return jdbcUserDetailsManager;
	}
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		return http.authorizeHttpRequests()
				.antMatchers("/admin").hasRole("ADMIN")
				.antMatchers("/user").hasAnyRole("ADMIN", "USER")
				.antMatchers("/").permitAll()
			.and()
				.formLogin()
			.and()
				.build();
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
}

package home.spring.security.springsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeResource {

	@GetMapping("/")
	public String home() {
		return "<h1>Hello World</h1>";
	}
	
	@GetMapping("/user")
	public String user() {
		return "<h1>Hello User</h1>";
	}
	
	@GetMapping("/admin")
	public String admin() {
		return "<h1>Hello Admin</h1>";
	}
}

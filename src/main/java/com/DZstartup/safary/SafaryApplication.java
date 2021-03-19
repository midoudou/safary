package com.DZstartup.safary;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.PropertySource;
import org.springframework.data.jpa.convert.threeten.Jsr310JpaConverters;

@SpringBootApplication
@EntityScan(basePackageClasses = {
	SafaryApplication.class,
	Jsr310JpaConverters.class
})
@PropertySource("classpath:security.properties")
public class SafaryApplication {

	public static void main(String[] args) {

		SpringApplication.run(SafaryApplication.class, args);
	}

}

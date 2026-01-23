package com.wso2.wso2.controller;

import com.wso2.wso2.entity.Student;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RequiredArgsConstructor
@RestController
public class TestController {

    @GetMapping("/hello")
    public String index(@AuthenticationPrincipal Jwt jwt) {
        return "Hello, " + jwt.getSubject() + ". Token accepted!";
    }

    @GetMapping("/students")
    public List<Student> students() {
        List<Student> students = new ArrayList<>();
        students.add(new Student("Wendmneh","Melake",22));
        students.add(new Student("Dawit","Tadegew",21));
        students.add(new Student("Yared","Tadesse",22));
        return students;
    }


    @GetMapping("/students/{name}")
    public Student getStudent(
            @PathVariable String name
    ) {
        List<Student> students = new ArrayList<>();
        students.add(new Student("Wendmneh","Melake",22));
        students.add(new Student("Dawit","Tadegew",21));
        students.add(new Student("Yared","Tadesse",22));

        return students.stream().filter(s->
                s.getFirstName().equalsIgnoreCase(name))
                .findFirst().orElse(null);
    }
}

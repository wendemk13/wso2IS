package com.wso2.wso2.entity;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class Student {
    private String firstName;
    private String lastName;
    private int age;

}

package com.example.demo.domain.user.controller;

import com.example.demo.domain.user.dto.UserSignUpDto;
import com.example.demo.domain.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
@RequiredArgsConstructor
@Slf4j
public class UserController {
    private final UserService userService;

    @PostMapping("/sign-up")
    public String signUp(@RequestBody UserSignUpDto userSignUpDto) throws Exception {
        log.info("[UserController sign-up : userSignUpDto : {}]", userSignUpDto.getNickname());
        userService.signUp(userSignUpDto);  //TODO 예외를 RestAdviceController 에서 받아올 수 있도록 수정
        return "회원가입 성공";
    }

    @GetMapping("/jwt-test")
    public String jwtTest() {
        return "jwtTest 요청 성공";
    }

}

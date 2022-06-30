package ru.kata.spring.boot_security.demo.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.demo.models.Role;
import ru.kata.spring.boot_security.demo.models.User;
import ru.kata.spring.boot_security.demo.services.UserService;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Controller
public class AdminController {

    private final UserService userService;

    @Autowired
    public AdminController(UserService userService) {
        this.userService = userService;
    }

    @RequestMapping("/admin")
    public String allUsers(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        User user = (User) userService.loadUserByUsername(userDetails.getUsername());
        model.addAttribute("addedUser", new User());
        model.addAttribute("roles", userService.allRoles());
        model.addAttribute("userRoles", user.getRoles());
        model.addAttribute("users", userService.allUsers());
        return "admin";
    }

    @PostMapping("/admin/addUser")
    public String addUser(@ModelAttribute User user,
                          @RequestParam(value = "roleChoice", required = false) Long[] roleChoice) {
        Set<Role> roles = new HashSet<>();
        if (roleChoice != null) {
            for (long i : roleChoice) {
                roles.add(userService.findRoleById(i));
            }
        } else {
            roles.add(userService.findRoleById(2L));
        }
        user.setRoles(roles);
        userService.addUser(user);
        return "redirect:/admin";
    }

    @GetMapping("/admin/removeUser/{id}")
    public String removeUser(@PathVariable("id") Long id) {
        userService.removeUser(id);
        return "redirect:/admin";
    }

    @PostMapping("/admin/editUser/{id}")
    public String editUser(@ModelAttribute User user,
                           @RequestParam(value = "roleChoice", required = false) Long[] roleChoice) {
        Set<Role> roles = new HashSet<>();
        if (roleChoice != null) {
            for (long i : roleChoice) {
                roles.add(userService.findRoleById(i));
            }
        } else {
            roles.add(userService.findRoleById(2L));
        }
        user.setRoles(roles);
        userService.saveAndFlush(user);
        return"redirect:/admin";
}
}

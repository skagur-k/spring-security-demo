package com.skagur.jwtdemo.service;

import com.skagur.jwtdemo.domain.Role;
import com.skagur.jwtdemo.domain.User;
import java.util.List;

public interface UserService {
    public User saveUser(User user);
    public Role saveRole(Role role);
    public void addRoleToUser(String username, String roleName);
    public User getUser(String username);
    public List<User> getUsers();
}

package com.opethic.hrms.HRMSNew.controllers.master;

import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.services.master.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class RoleController {
    @Autowired
    private RoleService roleService;

    @PostMapping(path = "/register_role")
    public Object createRole(HttpServletRequest request) {
        JsonObject res = roleService.addRole(request);
        return res.toString();
    }

    @PostMapping(path = "/get_role_by_id")
    public Object getRoleById(HttpServletRequest requestParam) {
        JsonObject response = roleService.getRolesById(requestParam.getParameter("roleId"));
        return response.toString();
    }

    @PostMapping(path = "/get_role_by_id_for_edit")
    public Object getRoleByIdForEdit(HttpServletRequest requestParam) {
        JsonObject response = roleService.getRoleByIdForEdit(requestParam);
        return response.toString();
    }

    @PostMapping(path = "/update_role")
    public ResponseEntity<?> updateRole(HttpServletRequest request) {
        return ResponseEntity.ok(roleService.updateRole(request));
    }

    @PostMapping(path="/remove_role")
    public Object removeRole(HttpServletRequest request)
    {
        JsonObject result=roleService.removerRole(request);
        return result.toString();
    }

    @PostMapping(path = "/get_role_permissions")
    public Object getRolePermissions(HttpServletRequest request) {
        JsonObject res = roleService.getRolePermissions(request);
        return res.toString();
    }

    @GetMapping(path = "/get_all_roles")
    public Object getAllRoles(HttpServletRequest request) {
        JsonObject res = roleService.getAllRoles(request);
        return res.toString();
    }
}

package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.opethic.hrms.HRMSNew.common.CommonAccessPermissions;
import com.opethic.hrms.HRMSNew.models.access_permissions.RoleAccessPermissions;
import com.opethic.hrms.HRMSNew.models.access_permissions.SystemAccessPermissions;
import com.opethic.hrms.HRMSNew.models.access_permissions.SystemActionMapping;
import com.opethic.hrms.HRMSNew.models.access_permissions.SystemMasterModules;
import com.opethic.hrms.HRMSNew.models.master.Company;
import com.opethic.hrms.HRMSNew.models.master.Role;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.access_permissions_repositories.RoleAccessPermissionsRepository;
import com.opethic.hrms.HRMSNew.repositories.access_permissions_repositories.SystemAccessPermissionsRepository;
import com.opethic.hrms.HRMSNew.repositories.access_permissions_repositories.SystemActionMappingRepository;
import com.opethic.hrms.HRMSNew.repositories.access_permissions_repositories.SystemMasterModuleRepository;
import com.opethic.hrms.HRMSNew.repositories.master.CompanyRepository;
import com.opethic.hrms.HRMSNew.repositories.master.RoleRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
@Service
public class RoleService {

    @Autowired
    private SystemMasterModuleRepository systemMasterModulesRepository;
    @Autowired
    private SystemAccessPermissionsRepository systemAccessPermissionsRepository;
    @Autowired
    private RoleAccessPermissionsRepository roleAccessPermissionsRepository;
    @Autowired
    private SystemActionMappingRepository systemActionMappingRepository;
    @Autowired
    private JwtTokenUtil jwtRequestFilter;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private CompanyRepository companyRepository;
    @Autowired
    private CommonAccessPermissions accessPermissions;

    private static final Logger roleLogger = LogManager.getLogger(RoleService.class);
    public JsonObject addRole(HttpServletRequest request) {
        Map<String, String[]> paramMap = request.getParameterMap();
        //  ResponseMessage responseObject = new ResponseMessage();
        JsonObject responseObject = new JsonObject();
        Role roleMaster = new Role();
        Users user = null;
        try {
            Role roleTest = roleRepository.findByRoleNameAndStatus(request.getParameter("roleName"),true);
            if(roleTest != null){
                roleLogger.error("Role with this name already exists");
                System.out.println("Role with this name already exists");
                responseObject.addProperty("responseStatus", HttpStatus.CONFLICT.value());
                responseObject.addProperty("message", "Role already exists");
                return responseObject;
            }

            roleMaster.setRoleName(request.getParameter("roleName"));
            roleMaster.setStatus(true);
            if (request.getHeader("Authorization") != null) {
                user = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
                roleMaster.setCreatedBy(user.getId());
                if(user.getUserRole() != null && user.getUserRole().equalsIgnoreCase("CADMIN")) {
                    roleMaster.setCompany(user.getCompany());
                } else if(user.getUserRole() != null && user.getUserRole().equalsIgnoreCase("BADMIN")) {
                    roleMaster.setCompany(user.getCompany());
                    roleMaster.setBranch(user.getBranch());
                }
            }
//            if (paramMap.containsKey("companyId")) {
//                Company company = companyRepository.findByIdAndStatus(Long.parseLong(request.getParameter("companyId")), true);
//                roleMaster.setCompany(company);
//                roleMaster.setBranch(user.getBranch());
//            }
            Role newRole = roleRepository.save(roleMaster);
            try {
                /* Create Permissions */
                String jsonStr = request.getParameter("roles_permissions");
                if (jsonStr != null) {
                    JsonArray userPermissions = new JsonParser().parse(jsonStr).getAsJsonArray();
                    for (int i = 0; i < userPermissions.size(); i++) {
                        JsonObject mObject = userPermissions.get(i).getAsJsonObject();
                        RoleAccessPermissions mPermissions = new RoleAccessPermissions();
                        mPermissions.setRoleMaster(newRole);
                        SystemActionMapping mappings = systemActionMappingRepository.findByIdAndStatus(mObject.get("mapping_id").getAsLong(),
                                true);
                        mPermissions.setSystemActionMapping(mappings);
                        mPermissions.setStatus(true);
                        mPermissions.setCreatedBy(user.getId());
                        JsonArray mActionsArray = mObject.get("actions").getAsJsonArray();
                        String actionsId = "";
                        for (int j = 0; j < mActionsArray.size(); j++) {
                            actionsId = actionsId + mActionsArray.get(j).getAsString();
                            if (j < mActionsArray.size() - 1) {
                                actionsId = actionsId + ",";
                            }
                        }
                        mPermissions.setUserActionsId(actionsId);
                        roleAccessPermissionsRepository.save(mPermissions);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
                roleLogger.error("Exception in Role Master: " + e.getMessage());
                System.out.println(e.getMessage());
            }
            responseObject.addProperty("message", "Role master created successfully");
            responseObject.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (DataIntegrityViolationException e1) {
            e1.printStackTrace();
            roleLogger.error("Exception in addUser: " + e1.getMessage());
            System.out.println("DataIntegrityViolationException " + e1.getMessage());
            responseObject.addProperty("responseStatus", HttpStatus.CONFLICT.value());
            responseObject.addProperty("message", "Usercode already used");
            return responseObject;
        } catch (Exception e) {
            e.printStackTrace();
            roleLogger.error("Exception in addUser: " + e.getMessage());
            responseObject.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
            responseObject.addProperty("message", "Internal Server Error");
            e.printStackTrace();
            System.out.println("Exception:" + e.getMessage());
        }
        return responseObject;
    }

    public JsonObject getRolesById(String id) {
        Role role = roleRepository.findByIdAndStatus(Long.parseLong(id), true);
        JsonObject result = new JsonObject();
        result.addProperty("message", "success");
        result.addProperty("responseStatus", HttpStatus.OK.value());
        JsonArray role_permission = new JsonArray();
        if (role != null) {
            /***** get Role Permissions from access_permissions_tbl ****/
            List<RoleAccessPermissions> accessPermissions = new ArrayList<>();
            accessPermissions = roleAccessPermissionsRepository.findByRoleMasterIdAndStatus(role.getId(), true);

            for (RoleAccessPermissions mPermissions : accessPermissions) {
                JsonObject masterObject = new JsonObject();
                JsonObject mObject = new JsonObject();

                SystemMasterModules parentModule = systemMasterModulesRepository.findByIdAndStatus(
                        mPermissions.getSystemActionMapping().getSystemMasterModules().getParentModuleId(), true);
                if (parentModule != null) {
                    masterObject.addProperty("id", parentModule.getId());
                    masterObject.addProperty("name", parentModule.getName());
                } else {
                    masterObject.addProperty("id", mPermissions.getSystemActionMapping().getSystemMasterModules().getId());
                    masterObject.addProperty("name", mPermissions.getSystemActionMapping().getSystemMasterModules().getName());
                }
                mObject.addProperty("id", mPermissions.getSystemActionMapping().getId());
                mObject.addProperty("name", mPermissions.getSystemActionMapping().getName());
                JsonArray actions = new JsonArray();
                String actionsId = mPermissions.getUserActionsId();
                String[] actionsList = actionsId.split(",");
                Arrays.sort(actionsList);
                for (String actionId : actionsList) {
                    actions.add(actionId);
                }
                mObject.add("actions", actions);
                masterObject.add("level", mObject);
                role_permission.add(masterObject);
            }
            result.add("level", role_permission);
            result.addProperty("roleName", role.getRoleName());
        } else {
            result.addProperty("message", "error");
            result.addProperty("responseStatus", HttpStatus.FORBIDDEN.value());
        }
        return result;
    }

    public JsonObject getRoleByIdForEdit(HttpServletRequest request) {
        Long id = Long.valueOf(request.getParameter("role_id"));
        Role roleMaster = roleRepository.findByIdAndStatus(id, true);
        JsonObject response = new JsonObject();
        JsonObject result = new JsonObject();
        JsonArray user_permission = new JsonArray();
        if (roleMaster != null) {
            response.addProperty("id", roleMaster.getId());
            response.addProperty("roleId", roleMaster.getId());
            response.addProperty("roleName", roleMaster.getRoleName());


            /***** get User Permissions from access_permissions_tbl ****/
            List<RoleAccessPermissions> accessPermissions = new ArrayList<>();

            accessPermissions = roleAccessPermissionsRepository.findByRoleMasterIdAndStatus(roleMaster.getId(), true);
            for (RoleAccessPermissions mPermissions : accessPermissions) {
                JsonObject mObject = new JsonObject();
                mObject.addProperty("mapping_id", mPermissions.getSystemActionMapping().getId());
                JsonArray actions = new JsonArray();
                String actionsId = mPermissions.getUserActionsId();
                String[] actionsList = actionsId.split(",");
                Arrays.sort(actionsList);
                for (String actionId : actionsList) {
                    actions.add(actionId);
                }
                mObject.add("actions", actions);
                user_permission.add(mObject);
            }
            response.add("permissions", user_permission);
            result.addProperty("message", "success");
            result.addProperty("responseStatus", HttpStatus.OK.value());

            result.add("responseObject", response);
        } else {
            result.addProperty("message", "error");
            result.addProperty("responseStatus", HttpStatus.FORBIDDEN.value());
        }
        return result;
    }

    public Object updateRole(HttpServletRequest request) {
        Map<String, String[]> paramMap = request.getParameterMap();
        ResponseMessage responseObject = new ResponseMessage();
        Users user = new Users();
        Role roleMaster = roleRepository.findByIdAndStatus(Long.parseLong(request.getParameter("role_id")),
                true);
        List<SystemAccessPermissions> systemAccessPermissions = systemAccessPermissionsRepository.findByUserRoleIdAndStatus(Long.parseLong(request.getParameter("role_id")), true);
        if (systemAccessPermissions != null && systemAccessPermissions.size() > 0) {
            responseObject.setResponseStatus(HttpStatus.FORBIDDEN.value());
            responseObject.setMessage("Role is assigned to someone, you cannot update.");
        } else {
            if (roleMaster != null) {
                if (paramMap.containsKey("roleName")) {
                    roleMaster.setRoleName(request.getParameter("roleName"));
                }
                if (request.getHeader("Authorization") != null) {
                    user = jwtRequestFilter.getUserDataFromToken(
                            request.getHeader("Authorization").substring(7));
                    roleMaster.setCreatedBy(user.getId());
                    roleMaster.setCompany(user.getCompany());
                    roleMaster.setBranch(user.getBranch());
                }
                /* Update Permissions */
                String jsonStr = request.getParameter("role_permissions");
                JsonArray userPermissions = new JsonParser().parse(jsonStr).getAsJsonArray();
                for (int i = 0; i < userPermissions.size(); i++) {
                    JsonObject mObject = userPermissions.get(i).getAsJsonObject();
                    SystemActionMapping mappings = systemActionMappingRepository.findByIdAndStatus(mObject.get("mapping_id").getAsLong(),
                            true);
                    RoleAccessPermissions mPermissions = roleAccessPermissionsRepository.findByRoleMasterIdAndStatusAndSystemActionMappingId(
                            roleMaster.getId(), true, mappings.getId());
                    if (mPermissions != null) {
                        JsonArray mActionsArray = mObject.get("actions").getAsJsonArray();
                        String actionsId = "";
                        for (int j = 0; j < mActionsArray.size(); j++) {
                            actionsId = actionsId + mActionsArray.get(j).getAsString();
                            if (j < mActionsArray.size() - 1) {
                                actionsId = actionsId + ",";
                            }
                        }
                        mPermissions.setUserActionsId(actionsId);
                    } else {
                        mPermissions = new RoleAccessPermissions();
                        JsonArray mActionsArray = mObject.get("actions").getAsJsonArray();
                        String actionsId = "";
                        for (int j = 0; j < mActionsArray.size(); j++) {
                            actionsId = actionsId + mActionsArray.get(j).getAsString();
                            if (j < mActionsArray.size() - 1) {
                                actionsId = actionsId + ",";
                            }
                        }
                        mPermissions.setUserActionsId(actionsId);
                    }
                    mPermissions.setRoleMaster(roleMaster);
                    mPermissions.setSystemActionMapping(mappings);
                    mPermissions.setStatus(true);
                    mPermissions.setCreatedBy(user.getId());

                    roleAccessPermissionsRepository.save(mPermissions);
                }
                String del_user_perm = request.getParameter("del_role_permissions");
                JsonArray deleteUserPermission = new JsonParser().parse(del_user_perm).getAsJsonArray();
                for (int j = 0; j < deleteUserPermission.size(); j++) {
                    Long moduleId = deleteUserPermission.get(j).getAsLong();
                    //  SystemActionMapping delMapping = mappingRepository.findByIdAndStatus(moduleId, true);
                    RoleAccessPermissions delPermissions = roleAccessPermissionsRepository.findByRoleMasterIdAndStatusAndSystemActionMappingId(
                            roleMaster.getId(), true, moduleId);
                    delPermissions.setStatus(false);
                    try {
                        roleAccessPermissionsRepository.save(delPermissions);
                    } catch (Exception e) {
                    }

                }
                roleRepository.save(roleMaster);
                responseObject.setMessage("User Role updated sucessfully");
                responseObject.setResponseStatus(HttpStatus.OK.value());
            } else {
                responseObject.setResponseStatus(HttpStatus.FORBIDDEN.value());
                responseObject.setMessage("Not found");
            }
        }
        return responseObject;
    }

    public JsonObject removerRole(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonObject jsonObject = new JsonObject();

        Role roleMaster = roleRepository.findByIdAndStatus(Long.parseLong(request.getParameter("role_id")),
                true);
        List<SystemAccessPermissions> systemAccessPermissions = systemAccessPermissionsRepository.findByUserRoleIdAndStatus(Long.parseLong(request.getParameter("role_id")), true);
        if (systemAccessPermissions != null && systemAccessPermissions.size() > 0) {
            jsonObject.addProperty("message", "Role is assigned to someone, you cannot delete.");
            jsonObject.addProperty("responseStatus", HttpStatus.FORBIDDEN.value());
        } else {
            try {
                roleMaster.setStatus(false);
                roleMaster.setUpdatedBy(users.getId());
                roleMaster.setCompany(users.getCompany());
                roleMaster.setBranch(users.getBranch());
                roleMaster.setUpdatedAt(LocalDateTime.now());
                roleRepository.save(roleMaster);
                jsonObject.addProperty("message", "Role Deleted Successfully");
                jsonObject.addProperty("responseStatus", HttpStatus.OK.value());
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Exception:" + e.getMessage());
                e.getMessage();
                e.printStackTrace();
            }
        }
        return jsonObject;
    }

    public JsonObject getRolePermissions(HttpServletRequest request) {
        /* getting Role Permissions */
        JsonObject finalResult = new JsonObject();
        JsonArray rolePermissions = new JsonArray();
        JsonArray permissions = new JsonArray();
        JsonArray masterModules = new JsonArray();
        System.out.println(request.getParameter("role_id"));
        Long roleId = Long.parseLong(request.getParameter("role_id"));
        List<RoleAccessPermissions> list = roleAccessPermissionsRepository.findByRoleMasterIdAndStatus(roleId, true);
        /*
         * Print elements using the forEach
         */
        for (RoleAccessPermissions mapping : list) {
            JsonObject mObject = new JsonObject();
            mObject.addProperty("id", mapping.getId());
            mObject.addProperty("role_name", mapping.getRoleMaster().getRoleName());

            mObject.addProperty("action_mapping_id", mapping.getSystemActionMapping().getId());
            mObject.addProperty("action_mapping_name", mapping.getSystemActionMapping().getSystemMasterModules().getName());
            mObject.addProperty("action_mapping_slug", mapping.getSystemActionMapping().getSystemMasterModules().getSlug());
            String[] actions = mapping.getUserActionsId().split(",");
            permissions = accessPermissions.getActions(actions);
            masterModules = accessPermissions.getParentMasters(mapping.getSystemActionMapping().getSystemMasterModules().getParentModuleId());
            mObject.add("actions", permissions);
            JsonObject jsonObject = new JsonObject();
            jsonObject.addProperty("id", mapping.getSystemActionMapping().getSystemMasterModules().getId());
            jsonObject.addProperty("name", mapping.getSystemActionMapping().getSystemMasterModules().getName());
            jsonObject.addProperty("slug", mapping.getSystemActionMapping().getSystemMasterModules().getSlug());
            masterModules.add(jsonObject);
            mObject.add("parent_modules", masterModules);
            rolePermissions.add(mObject);
        }
        finalResult.add("RoleActions", rolePermissions);
        return finalResult;
    }

    public JsonObject getAllRoles(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonArray result = new JsonArray();
        JsonObject res = new JsonObject();
        List<Role> list = new ArrayList<>();
        list = roleRepository.findByStatus(true);
        if (list.size() > 0) {
            for (Role role : list) {
                JsonObject response = new JsonObject();
                response.addProperty("id", role.getId());
                response.addProperty("name", role.getRoleName());
                response.addProperty("created_at", role.getCreatedAt().toString());
                result.add(response);
            }
            res.addProperty("message", "success");
            res.addProperty("responseStatus", HttpStatus.OK.value());
            res.add("responseObject", result);
        } else {
            res.addProperty("message", "empty list");
            res.addProperty("responseStatus", HttpStatus.OK.value());
            res.add("responseObject", result);
        }
        return res;
    }
}

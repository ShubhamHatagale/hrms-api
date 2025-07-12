package com.opethic.hrms.HRMSNew.services.master;


import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.opethic.hrms.HRMSNew.common.CommonAccessPermissions;
import com.opethic.hrms.HRMSNew.common.PasswordEncoders;
import com.opethic.hrms.HRMSNew.exception.ResourceNotFoundException;
import com.opethic.hrms.HRMSNew.models.ApiResponse;
import com.opethic.hrms.HRMSNew.models.access_permissions.SystemAccessPermissions;
import com.opethic.hrms.HRMSNew.models.access_permissions.SystemActionMapping;
import com.opethic.hrms.HRMSNew.models.master.*;
import com.opethic.hrms.HRMSNew.repositories.access_permissions_repositories.SystemAccessPermissionsRepository;
import com.opethic.hrms.HRMSNew.repositories.access_permissions_repositories.SystemActionMappingRepository;
import com.opethic.hrms.HRMSNew.repositories.master.*;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Service
public class UsersService implements UserDetailsService {
    @Autowired
    private CommonAccessPermissions accessPermissions;
    @Autowired
    private SystemAccessPermissionsRepository systemAccessPermissionsRepository;
    @Autowired
    private SystemAccessPermissionsRepository accessPermissionsRepository;
    @Autowired
    private SystemActionMappingRepository mappingRepository;
    @Autowired
    private UsersRepository usersRepository;
    @Autowired
    private PasswordEncoders bcryptEncoder;
    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtTokenUtil jwtTokenUtil;
    @Autowired
    private AppVersionRepository appVersionRepository;
    private static final Logger UserLogger = LogManager.getLogger(UsersService.class);

    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private CompanyRepository companyRepository;
    @Autowired
    private BranchRepository branchRepository;

//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        Users user = usersRepository.findByUsername(username).orElseThrow(() ->
//                new ResourceNotFoundException("User", "username :" + username, 0L));
//        return user;
//    }

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        Users user = usersRepository.findByUsername(userName);
        if (user == null) {
            throw new UsernameNotFoundException("User not found with username: " + userName);
        }
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
                new ArrayList<>());
    }

    public Object createSuperAdmin(HttpServletRequest request) {
        ApiResponse responseObject = new ApiResponse();
        Users users = new Users();
        users.setUsername(request.getParameter("username"));
        users.setIsSuperAdmin(true);
        users.setStatus(true);
        users.setPassword(passwordEncoder.encode(request.getParameter("password")));
        users.setPlainPassword(request.getParameter("password"));
        users.setUserRole("SADMIN");
        try {
            usersRepository.save(users);
            responseObject.setMessage("Super admin created sucessfully");
            responseObject.setResponseStatus(HttpStatus.OK.value());
        } catch (Exception e) {
            responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            responseObject.setMessage("Internal Server Error");
            e.printStackTrace();
            System.out.println("Exception:" + e.getMessage());
        }
        return responseObject;
    }

    public Object addUser(HttpServletRequest request) {
        ApiResponse responseObject = new ApiResponse();
        Users users = new Users();

//        if (request.getParameter("employeeId") != null) {
//            Employee employee = new Employee();
//            employee.setId(Long.valueOf(request.getParameter("employeeId")));
//            users.setEmployee(employee);
//        }
        users.setPermissions(request.getParameter("permissions"));
        users.setStatus(true);
        if (request.getHeader("Authorization") != null) {
            Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            users.setCreatedBy(user.getId());
            users.setUpdatedBy(user.getId());
        }
        users.setUsername(request.getParameter("username"));
        users.setPassword(passwordEncoder.encode(request.getParameter("password")));
        users.setPlainPassword(request.getParameter("password"));
        try {
            usersRepository.save(users);
            responseObject.setMessage("User added successfully");
            responseObject.setResponseStatus(HttpStatus.OK.value());
        } catch (Exception e) {

            responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            responseObject.setMessage("Internal Server Error");
            e.printStackTrace();
            System.out.println("Exception:" + e.getMessage());
        }
        return responseObject;
    }

    public Object findUser(String username) throws UsernameNotFoundException {
        Users users = usersRepository.findByUsernameAndStatus(username, true);
        if (users == null) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
        return users;
    }

    public JsonObject getVersionCode() {
        JsonObject responseMessage = new JsonObject();
        try {
            AppVersion appVersion = appVersionRepository.findById(Long.valueOf("1")).get();
            if (appVersion != null) {
                JsonObject appObject = new JsonObject();
                appObject.addProperty("id", appVersion.getId());
                appObject.addProperty("versionCode", appVersion.getVersionCode());
                appObject.addProperty("versionName", appVersion.getVersionName());

                responseMessage.add("response", appObject);
                responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                responseMessage.addProperty("message", "Version not found");
                responseMessage.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.addProperty("message", "Failed to load data");
            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public Users findUserByUsername(String username, String password) throws UsernameNotFoundException {
        try {
            Users users = usersRepository.findByUsernameAndStatus(username, true);
            if (passwordEncoder.matches(password, users.getPassword())) {
                return users;
            }
        }catch (Exception e){
            System.out.println("Trouble while getting user: "+e);
        }
        return null;
    }

    public JsonObject addBoUserWithRoles(HttpServletRequest request) {
        Map<String, String[]> paramMap = request.getParameterMap();
        //  ResponseMessage responseObject = new ResponseMessage();
        JsonObject responseObject = new JsonObject();
        Users users = new Users();
        Company company = null;
        Branch branch = null;
        Users user = null;
        try {
            Users userTest = usersRepository.findByUsernameAndStatus(request.getParameter("userName"),true);
            if(userTest != null){
                UserLogger.error("User with this name already exists");
                System.out.println("User with this name already exists");
                responseObject.addProperty("responseStatus", HttpStatus.CONFLICT.value());
                responseObject.addProperty("message", "User already exists");
                return responseObject;
            }
            users.setUsername(request.getParameter("userName"));
            users.setUserRole("badmin");
            if (paramMap.containsKey("companyId")) {
                company = companyRepository.findByIdAndStatus(Long.parseLong(request.getParameter("companyId")),true);
                users.setCompany(company);
            }
            if (paramMap.containsKey("branchId")) {
                branch = branchRepository.findByIdAndStatus(Long.parseLong(request.getParameter("branchId")), true);
                users.setBranch(branch);
            }
            Role role = roleRepository.findRoleById(Long.parseLong(request.getParameter("userRole")));
            users.setRole(role);
            users.setFullName(request.getParameter("fullName").toString());
            users.setStatus(true);
            users.setIsSuperAdmin(false);
            users.setIsAdmin(true);
            //  users.setPermissions(request.getParameter("permissions"));
            if (request.getHeader("Authorization") != null) {
                user = jwtTokenUtil.getUserDataFromToken(
                        request.getHeader("Authorization").substring(7));
                users.setCreatedBy(user.getId());
            }
            users.setPassword(bcryptEncoder.passwordEncoderNew().encode(
                    request.getParameter("password")));
            users.setPlainPassword(request.getParameter("password"));

            if (paramMap.containsKey("permissions"))
                users.setPermissions(request.getParameter("permissions"));
            Users newUser = usersRepository.save(users);
            try {
                /* Create Permissions */
                String jsonStr = request.getParameter("user_permissions");
                if (jsonStr != null) {
                    JsonArray userPermissions = new JsonParser().parse(jsonStr).getAsJsonArray();
                    for (int i = 0; i < userPermissions.size(); i++) {
                        JsonObject mObject = userPermissions.get(i).getAsJsonObject();
                        SystemAccessPermissions mPermissions = new SystemAccessPermissions();
                        mPermissions.setUsers(newUser);
                        SystemActionMapping mappings = mappingRepository.findByIdAndStatus(mObject.get("mapping_id").getAsLong(),
                                true);
                        mPermissions.setUserRole(role);
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
                        accessPermissionsRepository.save(mPermissions);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
                UserLogger.error("Exception in addBoUserWithRoles: " + e.getMessage());
                System.out.println(e.getMessage());
            }
            responseObject.addProperty("message", "User added succussfully");
            responseObject.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (DataIntegrityViolationException e1) {
            e1.printStackTrace();
            UserLogger.error("Exception in addBoUserWithRoles: " + e1.getMessage());
            System.out.println("DataIntegrityViolationException " + e1.getMessage());
            responseObject.addProperty("responseStatus", HttpStatus.CONFLICT.value());
            responseObject.addProperty("message", "Usercode already used");
            return responseObject;
        } catch (Exception e) {
            e.printStackTrace();
            UserLogger.error("Exception in addBoUserWithRoles: " + e.getMessage());
            responseObject.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
            responseObject.addProperty("message", "Internal Server Error");
            e.printStackTrace();
            System.out.println("Exception:" + e.getMessage());
        }
        return responseObject;
    }

    public JsonObject getReportingManagers(HttpServletRequest request) {
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonArray result = new JsonArray();
        JsonObject res = new JsonObject();
        List<Users> list = new ArrayList<>();
        list = usersRepository.getReportingManagersByCompanyId(users.getCompany().getId());
        if (list.size() > 0) {
            for (Users user : list) {
                JsonObject response = new JsonObject();
                response.addProperty("id", user.getId());
                response.addProperty("name", user.getFullName());
                response.addProperty("created_at", user.getCreatedAt().toString());
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

    public JsonObject getAllUsers(HttpServletRequest request) {
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonArray result = new JsonArray();
        JsonObject res = new JsonObject();
        List<Users> list = new ArrayList<>();
        if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("CADMIN")) {
            list = usersRepository.getUsersByCompanyId(users.getCompany().getId());
        } else if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("BADMIN")) {
            list = usersRepository.findByCompanyIdAndBranchIdAndStatus(users.getCompany().getId(), users.getBranch().getId(), true);
        }
        if (list.size() > 0) {
            for (Users user : list) {
                JsonObject response = new JsonObject();
                response.addProperty("id", user.getId());
                response.addProperty("name", user.getUsername());
                response.addProperty("created_at", user.getCreatedAt().toString());
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

    public JsonObject getUserPermissions(HttpServletRequest request) {
        /* getting User Permissions */
        JsonObject finalResult = new JsonObject();
        JsonArray userPermissions = new JsonArray();
        JsonArray permissions = new JsonArray();
        JsonArray masterModules = new JsonArray();
        Long userId = Long.parseLong(request.getParameter("user_id"));
        List<SystemAccessPermissions> list = systemAccessPermissionsRepository.findByUsersIdAndStatus(userId, true);
        /*
         * Print elements using the forEach
         */
        for (SystemAccessPermissions mapping : list) {
            JsonObject mObject = new JsonObject();
            mObject.addProperty("id", mapping.getId());
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
            userPermissions.add(mObject);
        }
        finalResult.add("userActions", userPermissions);
        return finalResult;
    }

    public JsonObject getUsersById(String id) {
        Users user = usersRepository.findByIdAndStatus(Long.parseLong(id), true);
        JsonObject response = new JsonObject();
        JsonObject result = new JsonObject();
        JsonArray user_permission = new JsonArray();
        if (user != null) {
            response.addProperty("id", user.getId());
//            response.addProperty("roleId", user.getRoleMaster().getId());
            response.addProperty("userRole", user.getUserRole());
            response.addProperty("password", user.getPlainPassword());
            response.addProperty("userName", user.getUsername());
            response.addProperty("roleId", user.getRole() != null ?user.getRole().getId() :null);
            response.addProperty("companyId", user.getCompany().getId());
            response.addProperty("branchId", user.getBranch() != null ? user.getBranch().getId(): null);
            response.addProperty("password", user.getPlainPassword());
            response.addProperty("fullname", user.getFullName());
            if(user.getUserRole() != null && user.getRole()!= null){
                Role roleMaster = roleRepository.getById(user.getRole().getId());
                response.addProperty("roleName", roleMaster != null ? roleMaster.getRoleName() : "");
            }

            /***** get User Permissions from access_permissions_tbl ****/
            List<SystemAccessPermissions> accessPermissions = new ArrayList<>();
            accessPermissions = systemAccessPermissionsRepository.findByUsersIdAndStatus(user.getId(), true);
            if(accessPermissions != null && accessPermissions.size() > 0) {
                for (SystemAccessPermissions mPermissions : accessPermissions) {
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
            }
            result.addProperty("message", "success");
            result.addProperty("responseStatus", HttpStatus.OK.value());

            result.add("responseObject", response);
        } else {
            result.addProperty("message", "error");
            result.addProperty("responseStatus", HttpStatus.FORBIDDEN.value());
        }
        return result;
    }

    public Object updateUser(HttpServletRequest request) {
        Map<String, String[]> paramMap = request.getParameterMap();
        ResponseMessage responseObject = new ResponseMessage();
        try{
            Users users = usersRepository.findByIdAndStatus(Long.parseLong(request.getParameter("user_id")),
                    true);
            if (users != null) {
                users.setUsername(request.getParameter("userName"));
//            users.setPassword(request.getParameter("password"));
                users.setPassword(bcryptEncoder.passwordEncoderNew().encode(request.getParameter("password")));
                users.setPlainPassword(request.getParameter("password"));

                Role userRole=roleRepository.findByIdAndStatus(Long.parseLong(request.getParameter("roleId")),true);
                if(userRole!=null)
                {
                    users.setRole(userRole);
//                    users.setUserRole(userRole.getRoleName());
                }
                //users.setUserRole(request.getParameter("userRole"));
//            users.setPermissions(request.getParameter("permissions"));
                if (request.getHeader("Authorization") != null) {
                    Users user = jwtTokenUtil.getUserDataFromToken(
                            request.getHeader("Authorization").substring(7));
                    users.setCreatedBy(user.getId());
                    users.setCompany(user.getCompany());
                    users.setBranch(user.getBranch());
                }
//            users.setPassword(bcryptEncoder.passwordEncoderNew().encode(request.getParameter("password")));
//            users.setPlain_password(request.getParameter("password"));

                /* Update Permissions */
                String jsonStr = request.getParameter("user_permissions");
                if (jsonStr != null) {
                    JsonArray userPermissions = new JsonParser().parse(jsonStr).getAsJsonArray();
                    for (int i = 0; i < userPermissions.size(); i++) {
                        JsonObject mObject = userPermissions.get(i).getAsJsonObject();
                        SystemActionMapping mappings = mappingRepository.findByIdAndStatus(mObject.get("mapping_id").getAsLong(),
                                true);
                        System.out.println(mappings.getId());
                        SystemAccessPermissions mPermissions = accessPermissionsRepository.findByUsersIdAndStatusAndSystemActionMappingId(
                                users.getId(), true, mappings.getId());
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
                            mPermissions = new SystemAccessPermissions();
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
                        mPermissions.setUsers(users);
                        mPermissions.setSystemActionMapping(mappings);
                        mPermissions.setStatus(true);
                        mPermissions.setCreatedBy(users.getId());
                        mPermissions.setUserRole(userRole);
                        try {
                            accessPermissionsRepository.save(mPermissions);
                        }catch (Exception exception){
                            System.out.println(exception);
                        }
                    }
                    String del_user_perm = request.getParameter("del_user_permissions");
                    JsonArray deleteUserPermission = new JsonParser().parse(del_user_perm).getAsJsonArray();
                    for (int j = 0; j < deleteUserPermission.size(); j++) {
                        Long moduleId = deleteUserPermission.get(j).getAsLong();
                        //  SystemActionMapping delMapping = mappingRepository.findByIdAndStatus(moduleId, true);
                        SystemAccessPermissions delPermissions = accessPermissionsRepository.findByUsersIdAndStatusAndSystemActionMappingId(
                                users.getId(), true, moduleId);
                        delPermissions.setStatus(false);
                        delPermissions.setCreatedBy(users.getId());
                        delPermissions.setUserRole(userRole);
                        try {
                            accessPermissionsRepository.save(delPermissions);
                        } catch (Exception e) {
                        }

                    }
                    usersRepository.save(users);
                    responseObject.setMessage("User updated sucessfully");
                    responseObject.setResponseStatus(HttpStatus.OK.value());
                } else {
                    responseObject.setResponseStatus(HttpStatus.FORBIDDEN.value());
                    responseObject.setMessage("Not found");
                }
            }  else{
                responseObject.setResponseStatus(HttpStatus.FORBIDDEN.value());
                responseObject.setMessage("Not found");
            }
        }catch (Exception e){
            System.out.println(e);
            responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            responseObject.setMessage("Something went wrong");
        }
        return responseObject;
    }

    public JsonObject removeUser(HttpServletRequest request) {
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("message", "User Not Found");
        jsonObject.addProperty("responseStatus", HttpStatus.FORBIDDEN.value());
        Users userToBeDeleted = usersRepository.findByIdAndStatus(Long.parseLong(request.getParameter("user_id")),true);
        List<SystemAccessPermissions> systemAccessPermissions = systemAccessPermissionsRepository.findByUsersIdAndStatus(userToBeDeleted.getId(),true);
        try {
            for(SystemAccessPermissions mPermission: systemAccessPermissions){
                mPermission.setStatus(false);
            }
            userToBeDeleted.setStatus(false);
            userToBeDeleted.setUpdatedBy(users.getId());
            users.setCompany(users.getCompany());
            users.setBranch(users.getBranch());
            userToBeDeleted.setUpdatedAt(LocalDateTime.now());
            usersRepository.save(userToBeDeleted);
            jsonObject.addProperty("message", "User Deleted Successfully");
            jsonObject.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception:" + e.getMessage());
            e.getMessage();
            e.printStackTrace();
        }
        return jsonObject;
    }

    public JsonObject activateDeactivateEmployee(HttpServletRequest request) {
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("message", "User Not Found");
        jsonObject.addProperty("responseStatus", HttpStatus.FORBIDDEN.value());
        boolean status = Boolean.parseBoolean(request.getParameter("status"));
        Users user = usersRepository.findByIdAndStatus(Long.parseLong(request.getParameter("user_id")),!status);
//        if(status)
//            user = userRepository.findByIdAndStatus(Long.parseLong(request.getParameter("user_id")),!status);
//        else
//            user = userRepository.findByIdAndStatus(Long.parseLong(request.getParameter("user_id")),!status);
        if(user != null){
            List<SystemAccessPermissions> systemAccessPermissions = systemAccessPermissionsRepository.findByUsersIdAndStatus(user.getId(),!status);
            try {
                for(SystemAccessPermissions mPermission: systemAccessPermissions){
                    mPermission.setStatus(status);
                }
                user.setStatus(status);
                user.setUpdatedBy(users.getId());
                users.setCompany(users.getCompany());
                users.setBranch(users.getBranch());
                user.setUpdatedAt(LocalDateTime.now());
                usersRepository.save(user);
                if(status) {
                    jsonObject.addProperty("message", "User Activated Successfully");
                    jsonObject.addProperty("responseStatus", HttpStatus.OK.value());
                } else {
                    jsonObject.addProperty("message", "User De-Activated Successfully");
                    jsonObject.addProperty("responseStatus", HttpStatus.OK.value());
                }
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Exception:" + e.getMessage());
                e.getMessage();
                e.printStackTrace();
            }
        }
        return jsonObject;
    }

    public Users findUserWithPassword(String usercode, String password) throws UsernameNotFoundException {
        Users users = usersRepository.findByUsername(usercode);
        if (passwordEncoder.matches(password, users.getPassword())) {
            return users;
        }
        return null;
    }
}

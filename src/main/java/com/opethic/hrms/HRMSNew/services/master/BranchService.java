package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.opethic.hrms.HRMSNew.models.access_permissions.SystemAccessPermissions;
import com.opethic.hrms.HRMSNew.models.access_permissions.SystemActionMapping;
import com.opethic.hrms.HRMSNew.models.master.Branch;
import com.opethic.hrms.HRMSNew.models.master.Role;
import com.opethic.hrms.HRMSNew.models.master.Shift;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.access_permissions_repositories.SystemAccessPermissionsRepository;
import com.opethic.hrms.HRMSNew.repositories.access_permissions_repositories.SystemActionMappingRepository;
import com.opethic.hrms.HRMSNew.repositories.master.BranchRepository;
import com.opethic.hrms.HRMSNew.repositories.master.RoleRepository;
import com.opethic.hrms.HRMSNew.repositories.master.UsersRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Service
public class BranchService {
    @PersistenceContext
    private EntityManager entityManager;
    @Autowired
    private BranchRepository branchRepository;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private SystemAccessPermissionsRepository systemAccessPermissionsRepository;
    @Autowired
    private SystemActionMappingRepository systemActionMappingRepository;
    @Autowired
    private UsersRepository usersRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    PasswordEncoder passwordEncoder;

    public Object createBranch(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseObject = new ResponseMessage();
        try {
            Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            Branch branch = new Branch();
            branch.setBranchName(requestParam.get("branchName"));
            branch.setBranchCode(requestParam.get("branchCode"));
            branch.setBranchLat(Double.valueOf(requestParam.get("branchLat")));
            branch.setBranchLong(Double.valueOf(requestParam.get("branchLong")));
            branch.setBranchRadius(Double.valueOf(requestParam.get("branchRadius")));
            branch.setStatus(true);
            branch.setCreatedBy(users.getId());
            branch.setCompany(users.getCompany());
            branch.setCreatedAt(LocalDateTime.now());
            try {
                Branch branch1 = branchRepository.save(branch);
                if(branch1 != null){
                    try {
                        Users userTest = usersRepository.findByUsernameAndStatus(requestParam.get("userName"),true);
                        if(userTest != null){
                            System.out.println("User with this name already exists");
                            responseObject.setResponseStatus(HttpStatus.CONFLICT.value());
                            responseObject.setMessage("Username already exists");
                            return responseObject;
                        } else {
                            userTest = new Users();
                            userTest.setUsername(requestParam.get("userName"));
                            userTest.setUserRole("badmin");
                            userTest.setCompany(branch1.getCompany());
                            userTest.setBranch(branch1);
                            Role role = roleRepository.findRoleById(Long.parseLong(requestParam.get("userRole")));
                            userTest.setRole(role);
                            userTest.setFullName(requestParam.get("fullName").toString());
                            userTest.setStatus(true);
                            userTest.setIsSuperAdmin(false);
                            userTest.setIsAdmin(true);
                            userTest.setPassword(passwordEncoder.encode(
                                    requestParam.get("password")));
                            userTest.setPlainPassword(requestParam.get("password"));

                            if (requestParam.containsKey("permissions"))
                                userTest.setPermissions(requestParam.get("permissions"));
                            Users newUser = usersRepository.save(userTest);
                            try {
                                /* Create Permissions */
                                String jsonStr = requestParam.get("user_permissions");
                                if (jsonStr != null) {
                                    JsonArray userPermissions = new JsonParser().parse(jsonStr).getAsJsonArray();
                                    for (int i = 0; i < userPermissions.size(); i++) {
                                        JsonObject mObject = userPermissions.get(i).getAsJsonObject();
                                        SystemAccessPermissions mPermissions = new SystemAccessPermissions();
                                        mPermissions.setUsers(newUser);
                                        SystemActionMapping mappings = systemActionMappingRepository.findByIdAndStatus(mObject.get("mapping_id").getAsLong(),
                                                true);
                                        mPermissions.setUserRole(role);
                                        mPermissions.setSystemActionMapping(mappings);
                                        mPermissions.setStatus(true);
                                        mPermissions.setCreatedBy(users.getId());
                                        JsonArray mActionsArray = mObject.get("actions").getAsJsonArray();
                                        String actionsId = "";
                                        for (int j = 0; j < mActionsArray.size(); j++) {
                                            actionsId = actionsId + mActionsArray.get(j).getAsString();
                                            if (j < mActionsArray.size() - 1) {
                                                actionsId = actionsId + ",";
                                            }
                                        }
                                        mPermissions.setUserActionsId(actionsId);
                                        systemAccessPermissionsRepository.save(mPermissions);
                                    }
                                }
                            } catch (Exception e) {
                                e.printStackTrace();
                                System.out.println(e.getMessage());
                            }
                        }
                    } catch (Exception e){
                        responseObject.setMessage("Failed to create branch user");
                        responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                    }
                }
                responseObject.setMessage("Branch created successfully");
                responseObject.setResponse(branch1);
                responseObject.setResponseStatus(HttpStatus.OK.value());
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Exception:" + e.getMessage());
                responseObject.setMessage("Failed to create branch");
                responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception:" + e.getMessage());
            responseObject.setMessage("Failed to create branch");
            responseObject.setResponseStatus(HttpStatus.BAD_REQUEST.value());
        }
        return responseObject;
    }

    public JsonObject findBranch(Map<String, String> requestParam) {
        JsonObject responseMessage = new JsonObject();
        JsonObject userObj = new JsonObject();
        try {
            Branch branch = branchRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")), true);
            if (branch != null) {
                JsonObject jsonObject = new JsonObject();
                jsonObject.addProperty("branch_id", branch.getId());
                jsonObject.addProperty("branchName", branch.getBranchName());
                jsonObject.addProperty("branchCode", branch.getBranchCode());
                jsonObject.addProperty("branchLat", branch.getBranchLat());
                jsonObject.addProperty("branchLong", branch.getBranchLong());
                jsonObject.addProperty("branchRadius", branch.getBranchRadius());
                jsonObject.addProperty("company", branch.getCompany().getCompanyName());
                Users user = usersRepository.findByCompanyIdAndBranchIdAndUserRoleAndStatus(branch.getCompany().getId(), branch.getId(), "badmin",true);
                if(user != null){
                    JsonArray user_permission = new JsonArray();
                    userObj.addProperty("userId", user.getId());
                    userObj.addProperty("userRole", user.getUserRole());
                    userObj.addProperty("password", user.getPlainPassword());
                    userObj.addProperty("userName", user.getUsername());
                    userObj.addProperty("roleId", user.getRole() != null ?user.getRole().getId() :null);
                    userObj.addProperty("companyId", user.getCompany().getId());
                    userObj.addProperty("branchId", user.getBranch() != null ? user.getBranch().getId(): null);
                    userObj.addProperty("password", user.getPlainPassword());
                    userObj.addProperty("fullname", user.getFullName());
                    if(user.getUserRole() != null && user.getRole()!= null){
                        Role roleMaster = roleRepository.getById(user.getRole().getId());
                        userObj.addProperty("roleName", roleMaster != null ? roleMaster.getRoleName() : "");
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
                        userObj.add("permissions", user_permission);
                    }
                    jsonObject.add("userObject", userObj);
                }
                responseMessage.add("response",jsonObject);
                responseMessage.addProperty("responseStatus",HttpStatus.OK.value());
            } else {
                responseMessage.addProperty("message","Data not found");
                responseMessage.addProperty("response",HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.addProperty("message","Data not found");
            responseMessage.addProperty("response",HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public Object updateBranch(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseObject = new ResponseMessage();
        try {
            Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            Branch branch = branchRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")), true);
            if (branch != null) {
                branch.setBranchName(requestParam.get("branchName"));
                branch.setBranchCode(requestParam.get("branchCode"));
                branch.setBranchLat(Double.valueOf(requestParam.get("branchLat")));
                branch.setBranchLong(Double.valueOf(requestParam.get("branchLong")));
                branch.setBranchRadius(Double.valueOf(requestParam.get("branchRadius")));
                branch.setUpdatedBy(user.getId());
                branch.setCompany(user.getCompany());
                branch.setUpdatedAt(LocalDateTime.now());
                try {
                    Branch branch1 = branchRepository.save(branch);
                    if(branch1 != null){
                        Users userTest = usersRepository.findByIdAndStatus(Long.parseLong(requestParam.get("user_id")),true);
                        if (userTest != null) {
                            userTest.setUsername(requestParam.get("userName"));
                            userTest.setPassword(passwordEncoder.encode(requestParam.get("password")));
                            userTest.setPlainPassword(requestParam.get("password"));
                            userTest.setFullName(requestParam.get("fullName").toString());
                            Role userRole=roleRepository.findByIdAndStatus(Long.parseLong(requestParam.get("roleId")),true);
                            if(userRole!=null)
                            {
                                userTest.setRole(userRole);
//                                userTest.setUserRole(userRole.getRoleName());
                            }

                            /* Update Permissions */
                            String jsonStr = requestParam.get("user_permissions");
                            if (jsonStr != null) {
                                JsonArray userPermissions = new JsonParser().parse(jsonStr).getAsJsonArray();
                                for (int i = 0; i < userPermissions.size(); i++) {
                                    JsonObject mObject = userPermissions.get(i).getAsJsonObject();
                                    SystemActionMapping mappings = systemActionMappingRepository.findByIdAndStatus(mObject.get("mapping_id").getAsLong(),
                                            true);
                                    System.out.println(mappings.getId());
                                    SystemAccessPermissions mPermissions = systemAccessPermissionsRepository.findByUsersIdAndStatusAndSystemActionMappingId(
                                            userTest.getId(), true, mappings.getId());
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
                                    mPermissions.setUsers(userTest);
                                    mPermissions.setSystemActionMapping(mappings);
                                    mPermissions.setStatus(true);
                                    mPermissions.setCreatedBy(userTest.getId());
                                    mPermissions.setUserRole(userRole);
                                    try {
                                        systemAccessPermissionsRepository.save(mPermissions);
                                    }catch (Exception exception){
                                        System.out.println(exception);
                                    }
                                }
                                String del_user_perm = requestParam.get("del_user_permissions");
                                if(del_user_perm != null) {
                                    JsonArray deleteUserPermission = new JsonParser().parse(del_user_perm).getAsJsonArray();
                                    for (int j = 0; j < deleteUserPermission.size(); j++) {
                                        Long moduleId = deleteUserPermission.get(j).getAsLong();
                                        //  SystemActionMapping delMapping = mappingRepository.findByIdAndStatus(moduleId, true);
                                        SystemAccessPermissions delPermissions = systemAccessPermissionsRepository.findByUsersIdAndStatusAndSystemActionMappingId(
                                                userTest.getId(), true, moduleId);
                                        delPermissions.setStatus(false);
                                        delPermissions.setCreatedBy(userTest.getId());
                                        delPermissions.setUserRole(userRole);
                                        try {
                                            systemAccessPermissionsRepository.save(delPermissions);
                                        } catch (Exception e) {
                                        }
                                    }
                                }
                                usersRepository.save(userTest);
                                responseObject.setMessage("Branch and user updated successfully");
                                responseObject.setResponseStatus(HttpStatus.OK.value());
                            } else {
                                responseObject.setResponseStatus(HttpStatus.FORBIDDEN.value());
                                responseObject.setMessage("Not found");
                            }
                        } else {
                            responseObject.setResponseStatus(HttpStatus.FORBIDDEN.value());
                            responseObject.setMessage("User Not found");
                        }
                    } else {
                        responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                        responseObject.setMessage("Failed to update branch");
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("Exception:" + e.getMessage());
                    responseObject.setMessage("Failed to update branch");
                    responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            } else {
                responseObject.setMessage("Data not found");
                responseObject.setResponseStatus(HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception:" + e.getMessage());
            responseObject.setMessage("Failed to update branch");
            responseObject.setResponseStatus(HttpStatus.BAD_REQUEST.value());
        }
        return responseObject;
    }

    public JsonObject listOfBranch(HttpServletRequest request) {
        JsonObject responseMessage = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        List<Branch> branchList = null;
        try {
            Users users = jwtTokenUtil.getUserDataFromToken(request .getHeader("Authorization").substring(7));
            if(users.getIsSuperAdmin()) {
                branchList = branchRepository.findByStatus(true);
            } else {
                branchList = branchRepository.findByCompanyIdAndStatus(users.getCompany().getId(), true);
            }
            for (Branch branch : branchList) {
                JsonObject jsonObject = new JsonObject();
                jsonObject.addProperty("id", branch.getId());
                jsonObject.addProperty("branchName", branch.getBranchName());
                jsonObject.addProperty("branchCode", branch.getBranchCode());
                jsonObject.addProperty("branchLat", branch.getBranchLat());
                jsonObject.addProperty("branchLong", branch.getBranchLong());
                jsonObject.addProperty("branchRadius", branch.getBranchRadius());
                jsonObject.addProperty("createdDate", branch.getCreatedAt().toString());
                jsonArray.add(jsonObject);
            }
            responseMessage.add("response", jsonArray);
            responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            System.out.println("Exception " + e.getMessage());
            e.printStackTrace();
            responseMessage.addProperty("message", "Failed to load data");
            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public Object deleteBranch(Map<String ,String>requestParam,HttpServletRequest request){
        ResponseMessage responseMessage=new ResponseMessage();
        try {
            Users users=jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            Branch branch=branchRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")),true);
            if (branch !=null){
                branch.setStatus(false);
                branch.setUpdatedAt(LocalDateTime.now());
                branch.setUpdatedBy(users.getId());
                branch.setCompany(users.getCompany());
                try {
                    branchRepository.save(branch);
                    responseMessage.setMessage("Branch Deleted Successfully");
                    responseMessage.setResponseStatus(HttpStatus.OK.value());
                }catch (Exception e){
                    e.printStackTrace();
                    System.out.println("Exception"+e.getMessage());
                    responseMessage.setMessage("Failed to Load Data");
                    responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                }

            } else{
                responseMessage.setMessage("Data Not Found");
                responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            }
        }catch (Exception e){
            e.printStackTrace();
            System.out.println("Exception:" +e.getMessage());
            responseMessage.setMessage("Failed to Delete Shift");
            responseMessage.setResponseStatus(HttpStatus.BAD_REQUEST.value());
        }
        return responseMessage;
    }
}

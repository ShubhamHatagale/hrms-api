package com.opethic.hrms.HRMSNew.controllers.master;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.opethic.hrms.HRMSNew.common.CommonAccessPermissions;
import com.opethic.hrms.HRMSNew.models.access_permissions.SystemAccessPermissions;
import com.opethic.hrms.HRMSNew.models.access_permissions.SystemMasterModules;
import com.opethic.hrms.HRMSNew.models.master.Branch;
import com.opethic.hrms.HRMSNew.models.master.Company;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.access_permissions_repositories.SystemAccessPermissionsRepository;
import com.opethic.hrms.HRMSNew.repositories.access_permissions_repositories.SystemMasterModuleRepository;
import com.opethic.hrms.HRMSNew.repositories.master.BranchRepository;
import com.opethic.hrms.HRMSNew.repositories.master.CompanyRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.services.master.UsersService;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;

@RestController
public class UserController {
    private final String SECRET_KEY = "m!j^d8#0en6j&rye8$$s%v)3f%i#ngm2e!%x1=s*h1ds&2ulqe&0ls";
    @Autowired
    UsersService userService;
    public static long ACCESS_VALIDITY = 24 * 60 * 60;
    public static long TOKEN_VALIDITY = 20 * 60 * 60;
    @Autowired
    JwtTokenUtil jwtUtil;
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    CompanyRepository companyRepository;
    @Autowired
    BranchRepository branchRepository;
    @Autowired
    SystemAccessPermissionsRepository systemAccessPermissionsRepository;
    @Autowired
    private CommonAccessPermissions accessPermissions;
    @Autowired
    private SystemMasterModuleRepository systemMasterModuleRepository;

    Logger userLogger = LoggerFactory.getLogger(UserController.class);

    @PostMapping(path = "/cr-sadmin")
    public ResponseEntity<?> createSuperAdmin(HttpServletRequest request) {
        return ResponseEntity.ok(userService.createSuperAdmin(request));
    }

    @PostMapping(path = "/add-user")
    public ResponseEntity<?> createUser(HttpServletRequest request) {
        return ResponseEntity.ok(userService.addUser(request));
    }

    @PostMapping(path = "/add_bo_user_with_roles")
    public Object addBoUserWithRoles(HttpServletRequest request) {
        JsonObject response = userService.addBoUserWithRoles(request);
        return response.toString();
    }

    @GetMapping(path = "/get_all_users")
    public Object getAllUsers(HttpServletRequest request) {
        JsonObject res = userService.getAllUsers(request);
        return res.toString();
    }

    @GetMapping(path = "/getReportingManagers")
    public Object getReportingManagers(HttpServletRequest request) {
        JsonObject res = userService.getReportingManagers(request);
        return res.toString();
    }

    /*** get access permissions of User *****/
    @PostMapping(path = "/get_user_permissions")
    public Object getUserPermissions(HttpServletRequest request) {
        JsonObject jsonObject = userService.getUserPermissions(request);
        return jsonObject.toString();
    }

    @PostMapping(path = "/get_user_by_id")
    public Object getUsersById(HttpServletRequest requestParam) {
        JsonObject response = userService.getUsersById(requestParam.getParameter("id"));
        return response.toString();
    }

    /**** update Users ****/
    @PostMapping(path = "/updateUser")
    public ResponseEntity<?> updateUser(HttpServletRequest request) {
        return ResponseEntity.ok(userService.updateUser(request));
    }

    @PostMapping(path="/remove_user")
    public Object removeRole(HttpServletRequest request)
    {
        JsonObject result=userService.removeUser(request);
        return result.toString();
    }

    @PostMapping(path="/activate_deactivate_employee")
    public Object activateDeactivateEmployee(HttpServletRequest request)
    {
        JsonObject result=userService.activateDeactivateEmployee(request);
        return result.toString();
    }

    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public Object createAuthenticateToken(@RequestBody Map<String, String> request,
                                                     HttpServletRequest req) {
        JsonObject responseMessage = new JsonObject();
        String username = request.get("username");
        String password = request.get("password");
        try {
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(username, password);
            authenticationManager.authenticate(authenticationToken);
            Users users = userService.findUserWithPassword(username, password);
            Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY.getBytes());
            JWTCreator.Builder jwtBuilder = JWT.create();
            String access_token = "";
            jwtBuilder.withSubject(users.getUsername());
            jwtBuilder.withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_VALIDITY * 1000));
            jwtBuilder.withIssuer(req.getRequestURI());
            jwtBuilder.withClaim("userId", users.getId());
            jwtBuilder.withClaim("isSuperAdmin", users.getIsSuperAdmin());
            jwtBuilder.withClaim("userRole", users.getUserRole());
            jwtBuilder.withClaim("userCode", users.getUsercode());
            jwtBuilder.withClaim("fullName", users.getFullName());
            Company outlet = null;
            Branch branch = null;
            if (users.getUserRole() != null && !users.getUserRole().equalsIgnoreCase("SADMIN")){
                if(users.getUserRole().equalsIgnoreCase("CADMIN"))
                    outlet = companyRepository.findByIdAndStatus(users.getCompany().getId(),true);
                else if (users.getUserRole().equalsIgnoreCase("BADMIN") || users.getUserRole().equalsIgnoreCase("USER")){
                    outlet = companyRepository.findByIdAndStatus(users.getCompany().getId(),true);
                    branch = branchRepository.findByIdAndStatus(users.getBranch().getId(),true);
                }
            }
            if (users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("CADMIN")) {
                jwtBuilder.withClaim("outletId", outlet.getId());
                jwtBuilder.withClaim("outletName", outlet.getCompanyName());
                jwtBuilder.withClaim("state", outlet.getRegStateId());
                List<Branch> brancheList = branchRepository.findByCompanyIdAndStatus(users.getCompany().getId(), true);
                JsonArray branchArray = new JsonArray();
                if(brancheList != null){
                    for(Branch mBranch : brancheList){
                        JsonObject jsonObject = new JsonObject();
                        jsonObject.addProperty("id", mBranch.getId());
                        jsonObject.addProperty("branchName", mBranch.getBranchName());
                        branchArray.add(jsonObject);
                    }
                    responseMessage.add("branchList",branchArray);
                }
//                jwtBuilder.withClaim("isMultiBranch", outlet.getIsMultiBranch() != null ? outlet.getIsMultiBranch() : false);
            } else if (users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("BADMIN") || users.getUserRole().equalsIgnoreCase("USER")) {
                jwtBuilder.withClaim("branchId", branch != null ? branch.getId().toString() : "");
                jwtBuilder.withClaim("branchName", branch != null ? branch.getBranchName() : "");
                jwtBuilder.withClaim("outletId", outlet.getId());
                jwtBuilder.withClaim("outletName", outlet.getCompanyName());
                jwtBuilder.withClaim("state", outlet.getRegStateId());
            } else {
                List<Company> companyList = companyRepository.findAllByStatus(true);
                JsonArray companyArray = new JsonArray();
                if(companyList != null){
                    for(Company mCompany : companyList){
                        JsonObject jsonObject = new JsonObject();
                        jsonObject.addProperty("id", mCompany.getId());
                        jsonObject.addProperty("companyName", mCompany.getCompanyName());
                        companyArray.add(jsonObject);
                    }
                    responseMessage.add("companyList",companyArray);
                }
            }
            JsonObject userObject = new JsonObject();
            userObject.addProperty("userId", users.getId());
            userObject.addProperty("isSuperAdmin", users.getIsSuperAdmin());
            userObject.addProperty("userRole", users.getUserRole());
            userObject.addProperty("userCode", users.getUsercode());
            userObject.addProperty("fullName", users.getFullName());
            responseMessage.add("userObject",userObject);

            jwtBuilder.withClaim("status", "OK");
            if(!users.getUserRole().equalsIgnoreCase("SADMIN")) {
                /* getting User Permissions */
                JsonObject finalResult = new JsonObject();
                JsonArray userPermissions = new JsonArray();
                JsonArray permissions = new JsonArray();
                JsonArray masterModules = new JsonArray();
                List<SystemAccessPermissions> list = systemAccessPermissionsRepository.findByUsersIdAndStatus(users.getId(), true);
                /*
                 * Print elements using the forEach
                 */
                for (SystemAccessPermissions mapping : list) {
                    JsonObject mObject = new JsonObject();
                    mObject.addProperty("id", mapping.getId());
                    mObject.addProperty("action_mapping_id", mapping.getId());
                    SystemMasterModules modules = systemMasterModuleRepository.findByIdAndStatus(mapping.getId(), true);
                    if(modules != null) {
                        mObject.addProperty("action_mapping_name", modules.getName());
                        mObject.addProperty("action_mapping_slug", modules.getSlug());
                        String[] actions = mapping.getUserActionsId().split(",");
                        permissions = accessPermissions.getActions(actions);
                        masterModules = accessPermissions.getParentMasters(modules.getParentModuleId());
                        mObject.add("actions", permissions);
                        JsonObject jsonObject = new JsonObject();
                        jsonObject.addProperty("id", modules.getId());
                        jsonObject.addProperty("name", modules.getName());
                        jsonObject.addProperty("slug", modules.getSlug());
                        masterModules.add(jsonObject);
                        mObject.add("parent_modules", masterModules);
                        userPermissions.add(mObject);
                    }
                }
                finalResult.add("userActions", userPermissions);
                responseMessage.add("response",finalResult);
            }

            /* end of User Permissions */
            //     jwtBuilder.withClaim("permission", "" + finalResult);
            access_token = jwtBuilder.sign(algorithm);
            JWTCreator.Builder builder = JWT.create();
            String refresh_token = "";
            builder.withSubject(users.getUsername());
            builder.withExpiresAt(new Date(System.currentTimeMillis() + TOKEN_VALIDITY * 1000));
            builder.withIssuer(req.getRequestURI());
            refresh_token = builder.sign(algorithm);
            Map<String, Claim> claims = new HashMap<>();
            DecodedJWT jwt = JWT.decode(access_token);
            claims = jwt.getClaims();
            System.out.println("claims " + claims.toString());
            System.out.println("claims " + claims.toString().length());
            System.out.println("Access token length " + access_token.length());
            System.out.println("Refresh token length " + refresh_token.length());
            Map<String, String> tokens = new HashMap<>();
            tokens.put("access_token", access_token);
            tokens.put("refresh_token", refresh_token);
            ObjectMapper objectMapper = new ObjectMapper();
            String json = null;
            try {
                json = objectMapper.writeValueAsString(tokens);
                System.out.println(json);
            } catch (JsonProcessingException e) {
                e.printStackTrace();
            }
            JsonParser parser = new JsonParser();
            JsonObject object = (JsonObject) parser.parse(json);
            responseMessage.addProperty("message","Login Successfully");
            responseMessage.add("responseObject",object);
            responseMessage.addProperty("responseStatus",HttpStatus.OK.value());

            // responseMessage.setData(bcryptEncoder.encrypt(users.getPermissions()));
        } catch (BadCredentialsException be) {
            be.printStackTrace();
            System.out.println("Exception " + be.getMessage());
            responseMessage.addProperty("message","Incorrect Username or Password");
            responseMessage.addProperty("responseStatus",HttpStatus.UNAUTHORIZED.value());
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.addProperty("message","Incorrect Username or Password");
            responseMessage.addProperty("responseStatus",HttpStatus.UNAUTHORIZED.value());
        }
        //   responseMessage.setData(jwtToken);
        return responseMessage.toString();
    }

//    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
//    public ResponseEntity<?> createAuthenticateToken(@RequestBody Map<String, String> request,
//                                                     HttpServletRequest req) throws Exception {
//        ResponseMessage responseMessage = new ResponseMessage();
//        String username = request.get("username");
//        String password = request.get("password");
//
//        try {
//            Users userDetails = userService.findUserByUsername(username, password);
//            System.out.println("userDetails : "+userDetails);
//            if (userDetails != null) {
//                Object jwtToken = jwtUtil.generateToken(req, userDetails.getUsername());
//
//                responseMessage.setMessage("Login success");
//                responseMessage.setResponse(jwtToken);
//
//                responseMessage.setResponseStatus(HttpStatus.OK.value());
//                System.out.println("login success");
//                return ResponseEntity.ok(responseMessage);
//            } else {
//                System.out.println("login fail");
//                responseMessage.setMessage("Incorrect username or password");
//                responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
//                return ResponseEntity.ok(responseMessage);
//            }
//        } catch (Exception e1) {
//            System.out.println(e1.getMessage());
//            System.out.println("login fail");
//            responseMessage.setMessage("User not found");
//            responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
//            return ResponseEntity.ok(responseMessage);
//        }
//    }


//    @PostMapping("/change-password")
//    public Object changePassword(@RequestBody Map<String, String> request, HttpServletRequest req) {
//        return userService.changePassword(request, req);
//    }

    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                String refresh_token = authorizationHeader.substring("Bearer ".length());
                System.out.println("refresh_token " + refresh_token);
                Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY.getBytes());
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(refresh_token);
                String username = decodedJWT.getSubject();
                Users user = (Users) userService.findUser(username);
                String access_token = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 60 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("username", user.getUsername())
                        .withClaim("status", "OK")
                        .withClaim("userId", user.getId())
                        .withClaim("isSuperAdmin", user.getIsSuperAdmin())
                        .sign(algorithm);

                String new_refresh_token = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 65 * 60 * 1000))
                        .withIssuer(request.getRequestURI())
                        .sign(algorithm);

                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", access_token);
                tokens.put("refresh_token", new_refresh_token);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);
            } catch (Exception exception) {
                response.setHeader("error", exception.getMessage());
                response.setStatus(FORBIDDEN.value());
                //response.sendError(FORBIDDEN.value());
                Map<String, String> error = new HashMap<>();
                error.put("error_message", exception.getMessage());
                error.put("message", "session destroyed plz login");
                response.setContentType(MimeTypeUtils.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }
        } else {
            throw new RuntimeException("Refresh token is missing");
        }
    }

    @GetMapping(path = "/getVersionCode")
    public Object getVersionCode() {
        return userService.getVersionCode().toString();
    }

    /*****for Sadmin Login, sdamin can only view cadmins ****/
//    @GetMapping(path = "/get_company_admins")
//    public Object getCompanyAdmins(HttpServletRequest httpServletRequest) {
//        JsonObject res = userService.getCompanyAdmins(httpServletRequest);
//        return res.toString();
//    }
}



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
    public ResponseEntity<String> createAuthenticateToken(@RequestBody Map<String, String> request, HttpServletRequest req) {
        JsonObject responseMessage = new JsonObject();
        String username = request.get("username");
        String password = request.get("password");

        try {
            // Authenticate using Spring Security
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);
            authenticationManager.authenticate(authToken);

            Users user = userService.findUserWithPassword(username, password);
            if (user == null) {
                throw new BadCredentialsException("Invalid credentials");
            }

            Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY.getBytes());
            JWTCreator.Builder jwtBuilder = JWT.create()
                    .withSubject(user.getUsername())
                    .withIssuer(req.getRequestURI())
                    .withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_VALIDITY * 1000))
                    .withClaim("userId", user.getId())
                    .withClaim("isSuperAdmin", user.getIsSuperAdmin())
                    .withClaim("userRole", user.getUserRole())
                    .withClaim("userCode", user.getUsercode())
                    .withClaim("fullName", user.getFullName());

            JsonObject userObject = new JsonObject();
            userObject.addProperty("userId", user.getId());
            userObject.addProperty("isSuperAdmin", user.getIsSuperAdmin());
            userObject.addProperty("userRole", user.getUserRole());
            userObject.addProperty("userCode", user.getUsercode());
            userObject.addProperty("fullName", user.getFullName());
            responseMessage.add("userObject", userObject);

            // Role-specific data
            Company outlet = null;
            Branch branch = null;

            if (!"SADMIN".equalsIgnoreCase(user.getUserRole())) {
                outlet = companyRepository.findByIdAndStatus(user.getCompany().getId(), true);
                if ("BADMIN".equalsIgnoreCase(user.getUserRole()) || "USER".equalsIgnoreCase(user.getUserRole())) {
                    branch = branchRepository.findByIdAndStatus(user.getBranch().getId(), true);
                }
            }

            if ("CADMIN".equalsIgnoreCase(user.getUserRole()) && outlet != null) {
                jwtBuilder.withClaim("outletId", outlet.getId());
                jwtBuilder.withClaim("outletName", outlet.getCompanyName());
                jwtBuilder.withClaim("state", outlet.getRegStateId());

                List<Branch> branchList = branchRepository.findByCompanyIdAndStatus(outlet.getId(), true);
                JsonArray branchArray = new JsonArray();
                for (Branch b : branchList) {
                    JsonObject bJson = new JsonObject();
                    bJson.addProperty("id", b.getId());
                    bJson.addProperty("branchName", b.getBranchName());
                    branchArray.add(bJson);
                }
                responseMessage.add("branchList", branchArray);
            } else if (("BADMIN".equalsIgnoreCase(user.getUserRole()) || "USER".equalsIgnoreCase(user.getUserRole())) && outlet != null && branch != null) {
                jwtBuilder.withClaim("branchId", branch.getId());
                jwtBuilder.withClaim("branchName", branch.getBranchName());
                jwtBuilder.withClaim("outletId", outlet.getId());
                jwtBuilder.withClaim("outletName", outlet.getCompanyName());
                jwtBuilder.withClaim("state", outlet.getRegStateId());
            } else if ("SADMIN".equalsIgnoreCase(user.getUserRole())) {
                List<Company> companyList = companyRepository.findAllByStatus(true);
                JsonArray companyArray = new JsonArray();
                for (Company c : companyList) {
                    JsonObject cJson = new JsonObject();
                    cJson.addProperty("id", c.getId());
                    cJson.addProperty("companyName", c.getCompanyName());
                    companyArray.add(cJson);
                }
                responseMessage.add("companyList", companyArray);
            }

            // Permissions
            if (!"SADMIN".equalsIgnoreCase(user.getUserRole())) {
                List<SystemAccessPermissions> permissionsList = systemAccessPermissionsRepository.findByUsersIdAndStatus(user.getId(), true);
                JsonArray userPermissions = new JsonArray();

                for (SystemAccessPermissions perm : permissionsList) {
                    JsonObject permJson = new JsonObject();
                    SystemMasterModules module = systemMasterModuleRepository.findByIdAndStatus(perm.getId(), true);
                    if (module != null) {
                        permJson.addProperty("id", perm.getId());
                        permJson.addProperty("action_mapping_id", perm.getId());
                        permJson.addProperty("action_mapping_name", module.getName());
                        permJson.addProperty("action_mapping_slug", module.getSlug());

                        String[] actions = perm.getUserActionsId().split(",");
                        permJson.add("actions", accessPermissions.getActions(actions));
                        permJson.add("parent_modules", accessPermissions.getParentMasters(module.getParentModuleId()));

                        userPermissions.add(permJson);
                    }
                }

                JsonObject result = new JsonObject();
                result.add("userActions", userPermissions);
                responseMessage.add("response", result);
            }

            // Final Tokens
            String accessToken = jwtBuilder.sign(algorithm);

            String refreshToken = JWT.create()
                    .withSubject(user.getUsername())
                    .withIssuer(req.getRequestURI())
                    .withExpiresAt(new Date(System.currentTimeMillis() + TOKEN_VALIDITY * 1000))
                    .sign(algorithm);

            JsonObject tokens = new JsonObject();
            tokens.addProperty("access_token", accessToken);
            tokens.addProperty("refresh_token", refreshToken);
            responseMessage.add("responseObject", tokens);
            responseMessage.addProperty("message", "Login Successfully");
            responseMessage.addProperty("responseStatus", HttpStatus.OK.value());

            return ResponseEntity.ok(responseMessage.toString());

        } catch (BadCredentialsException ex) {
            responseMessage.addProperty("message", "Incorrect Username or Password");
            responseMessage.addProperty("responseStatus", HttpStatus.UNAUTHORIZED.value());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseMessage.toString());
        } catch (Exception ex) {
            ex.printStackTrace();
            responseMessage.addProperty("message", "Authentication failed");
            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseMessage.toString());
        }
    }




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



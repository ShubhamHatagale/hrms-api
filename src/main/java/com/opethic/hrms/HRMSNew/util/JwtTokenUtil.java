package com.opethic.hrms.HRMSNew.util;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.opethic.hrms.HRMSNew.models.master.Employee;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.services.master.EmployeeService;
import com.opethic.hrms.HRMSNew.services.master.UsersService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtTokenUtil {
    private final String SECRET_KEY = "m!j^d8#0en6j&rye8$$s%v)3f%i#ngm2e!%x1=s*h1ds&2ulqe&0ls";
    @Autowired
    private UsersService userService;
    @Autowired
    private EmployeeService employeeService;
    @Autowired
    Utility utility;


    public Users getUserDataFromToken(String jwtToken) {
        Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY.getBytes());
        System.out.println("jwtToken--"+jwtToken);
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = verifier.verify(jwtToken);
        String username = decodedJWT.getSubject();
        if (username != null) {
            Users user = (Users) userService.findUser(username);
            return user;
        }
        return null;
    }

    public Employee getEmployeeDataFromToken(String jwtToken) {
        Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY.getBytes());
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = verifier.verify(jwtToken);
        String username = decodedJWT.getSubject();
        if (username != null) {
            Employee employee = (Employee) employeeService.findEmp(Long.valueOf(username));
            return employee;
        }
        return null;
    }

    public Map<String, String> generateToken(HttpServletRequest req, String username) {
        Users users = (Users) userService.findUser(username);
        Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY.getBytes());

//        JsonObject jsonObject = new JsonObject();
//        jsonObject.addProperty("username", users.getUsername());
//        jsonObject.addProperty("status", "OK");
//        jsonObject.addProperty("userId", users.getId());
//        jsonObject.addProperty("isSuperAdmin", false);
//
//        System.out.println("jsonObject length " + jsonObject);
//        System.out.println("jsonObject length " + jsonObject.toString().length());
        String access_token = JWT.create()
                .withSubject(users.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + (60 * 24) * 60 * 1000)) // (60 min * 24 => 24 Hrs)
                .withIssuer(req.getRequestURI())
                .withClaim("username", users.getUsername())
                .withClaim("companyId", users.getCompany() != null ? users.getCompany().getId() : 0)
                .withClaim("branchId", users.getBranch() != null ? users.getBranch().getId() : 0)
                .withClaim("isAdmin", users.getIsAdmin() != null ? users.getIsAdmin() : false)
                .withClaim("status", "OK")
                .withClaim("userId", users.getId())
                .withClaim("isSuperAdmin", users.getIsSuperAdmin())
                .sign(algorithm);

        String refresh_token = JWT.create()
                .withSubject(users.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + (60 * 30) * 60 * 1000))
                .withIssuer(req.getRequestURI())
                .sign(algorithm);

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

        return tokens;
    }

    public Map<String, String> generateTokenForMobile(HttpServletRequest req, String username) {
        Employee employee = (Employee) employeeService.findEmp(Long.parseLong(username));

        Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY.getBytes());
        String access_token = JWT.create()
                .withSubject(employee.getMobileNumber().toString())
                .withExpiresAt(new Date(System.currentTimeMillis() + (60 * 20) * 60 * 1000))
                .withIssuer(req.getRequestURI())
                .withClaim("employeeName", utility.getEmployeeName(employee))
                .withClaim("designationName", employee.getDesignation().getDesignationName())
                .withClaim("designationLevel", employee.getDesignation().getLevel().getLevelName())
                .withClaim("username", employee.getMobileNumber().toString())
                .withClaim("userId", employee.getId())
                .withClaim("doj", employee.getDoj().toString())
                .withClaim("address", employee.getPermanentAddress() != null ? employee.getPermanentAddress() : "NA")
                .withClaim("isSuperAdmin", false)
                .withClaim("branchName", employee.getBranch() != null ?
                        employee.getBranch().getBranchName() : "NA")
                .withClaim("branchCode", employee.getBranch() != null ?
                        employee.getBranch().getBranchCode() : "NA")
                .withClaim("branchLat", employee.getBranch() != null ?
                        employee.getBranch().getBranchLat().toString() : "NA")
                .withClaim("branchLong", employee.getBranch() != null ?
                        employee.getBranch().getBranchLong().toString() : "NA")
                .withClaim("branchRadius", employee.getBranch() != null ?
                        employee.getBranch().getBranchRadius().toString() : "NA")
                .withClaim("showSalarySheet", employee.getShowSalarySheet() != null ?
                        employee.getShowSalarySheet().toString() : "NA")
                .sign(algorithm);

        String refresh_token = JWT.create()
                .withSubject(employee.getMobileNumber().toString())
                .withExpiresAt(new Date(System.currentTimeMillis() + (60 * 24) * 60 * 1000))
                .withIssuer(req.getRequestURI())
                .sign(algorithm);

        System.out.println("Access token length " + access_token);
        System.out.println("Access token length " + access_token.length());
        System.out.println("Refresh token length " + refresh_token.length());

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", access_token);
        tokens.put("refresh_token", refresh_token);

        return tokens;
    }
}

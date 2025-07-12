package com.opethic.hrms.HRMSNew.models.master;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Data
@Entity
@Table(name = "employee_tbl")
public class Employee {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String fullName;
    private String firstName;
    private String middleName;
    private String lastName;
    @Column(unique = true)
    private Long mobileNumber;
    private String gender;
    private LocalDate dob;
    private Integer age;
    private String cast;
    private String reasonToJoin;
    private String religion;
    private String marriageStatus;
    private Double height;
    private Double weight;
    private String bloodGroup;
    private Boolean isDisability;
    private String disabilityDetails;
    private Boolean isInjured;
    private String injureDetails;
    private String hobbies;
    private String presentAddress;
    private String permanentAddress;
    private String correspondenceAddress;
    private Double wagesPerDay;
    private Boolean employeeHavePf;
    private Double employerPf;
    private Double employeePf;
    private Boolean employeeHaveEsi;
    private Double employerEsi;
    private Double employeeEsi;
    private Boolean employeeHaveProfTax;
    private Boolean showSalarySheet;
    private String emergencyRelation;
    private String emergencyContact;
    @ManyToOne
//    @JsonIgnoreProperties(value = {"employee","hibernateLazyInitializer"})
    @JsonManagedReference
    @JoinColumn(name = "designation_id", nullable = false)
    private Designation designation;

    @ManyToOne
//    @JsonIgnoreProperties(value = {"employee","hibernateLazyInitializer"})
    @JsonManagedReference
    @JoinColumn(name = "shift_id")
    private Shift shift;

    @ManyToOne
//    @JsonIgnoreProperties(value = {"employee","hibernateLazyInitializer"})
    @JsonManagedReference
    @JoinColumn(name = "branch_id")
    private Branch branch;

    @ManyToOne
    @JsonManagedReference
    @JoinColumn(name = "company_id")
    private Company company;

    @ManyToOne
//    @JsonIgnoreProperties(value = {"employee","hibernateLazyInitializer"})
    @JsonManagedReference
    @JoinColumn(name = "department_id")
    private Department department;

    @ManyToOne
    @JsonManagedReference
    @JoinColumn(name = "users_id")
    private Users reportingManager;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<Attendance> attendanceList;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<EmployeeFamily> employeeFamily;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<EmployeeEducation> employeeEducation;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<EmployeeExperienceDetails> employeeExperienceDetails;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<EmployeeDocument> employeeDocuments;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<EmployeeReference> employeeReferences;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<EmployeePayhead> employeePayheadList;
//
    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<Break> breakList;
//
    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<EmployeeLeave> employeeLeaveList;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<EmployeePayroll> employeePayrollList;

    private String wagesOptions;
    private String employeeWagesType;
    private int weeklyOffDay;
    private Boolean isExperienceEmployee;
    private Double expectedSalary;
    private LocalDate effectedDate;
    private LocalDate doj;
    private String bankName;
    private String branchName;
    private String departmentName;
    private String accountNo;
    private String ifscCode;
    private String pfNumber;
    private String esiNumber;
    private String panNumber;
    private String textPassword;
    private String password;
    private String employeeType;
    private Long createdBy;
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Long updatedBy;
    private LocalDateTime updatedAt;
    private Boolean status;
}

package com.opethic.hrms.HRMSNew.models.master;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.opethic.hrms.HRMSNew.config.AppConfig;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Data
@Entity
@Table(name = "company_tbl")
public class Company {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String companyCode;
    private String companyName;
    private String companyType; // proprietorship,llp,pvt. ltd,ltd
    private String companyLogo;
    private String regAddress;
    private String regPincode;
    private String regArea;
    private Long regCityId;
    private Long regStateId;
    private Long regCountryId;
    private Boolean sameAsRegisterAddress;
    private String corpAddress;
    private String corpPincode;
    private String corpArea;
    private Long corpCityId;
    private Long corpStateId;
    private Long corpCountryId;
    private String licenseNo;
    private LocalDate licenseExpiryDate;
    private LocalDate holidayFromDate;
    private LocalDate holidayToDate;
    private String websiteUrl;
    private String emailId;
    private Long mobileNumber;
    private Long whatsappNumber;
    private String currency;
    private Boolean gstApplicable;
    private String gstNumber;
    private Long gstTypeId; // registered,composition
    private LocalDate gstApplicableDate;
    private Boolean isCompanyEsic;
    private Boolean isCompanyPf;
    private String pfRegistrationNumber;
    private Boolean isCompanyPt;
    private String ptRegistrationNumber;
    private Boolean status;
    @Column(updatable = false)
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Long createdBy;
    @Column(insertable = false)
    @UpdateTimestamp
    private LocalDateTime updatedAt;
    private Long updatedBy;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<AppConfig> appConfigs;
}

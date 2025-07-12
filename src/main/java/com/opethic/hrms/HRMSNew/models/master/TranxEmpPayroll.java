package com.opethic.hrms.HRMSNew.models.master;


import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.Data;

import javax.persistence.*;
import java.time.LocalDate;
import java.util.List;

@Data
@Entity
@Table(name="tranx_emp_payroll_tbl")
public class TranxEmpPayroll {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JsonIgnoreProperties(value = {"attendance", "hibernateLazyInitializer"})
    @JoinColumn(name = "employee_id", nullable = false)
    private Employee employee;

//    @ManyToOne
//    @JsonIgnoreProperties(value = {"attendance", "hibernateLazyInitializer"})
//    @JoinColumn(name = "basicSalary_id", nullable = false)
//    private LedgerMaster basicSalaryLedger;
//
//    @ManyToOne
//    @JsonIgnoreProperties(value = {"attendance", "hibernateLazyInitializer"})
//    @JoinColumn(name = "specialAllowance_id", nullable = false)
//    private LedgerMaster specialAllowanceLedger;
//
//    @ManyToOne
//    @JsonIgnoreProperties(value = {"attendance", "hibernateLazyInitializer"})
//    @JoinColumn(name = "pf_id")
//    private LedgerMaster pfLedger;
//
//    @ManyToOne
//    @JsonIgnoreProperties(value = {"attendance", "hibernateLazyInitializer"})
//    @JoinColumn(name = "esi_id")
//    private LedgerMaster esiLedger;
//
//    @ManyToOne
//    @JsonIgnoreProperties(value = {"attendance", "hibernateLazyInitializer"})
//    @JoinColumn(name = "pfTax_id")
//    private LedgerMaster pfTaxLedger;
//
//    @ManyToOne
//    @JsonIgnoreProperties(value = {"attendance", "hibernateLazyInitializer"})
//    @JoinColumn(name = "incentive_id")
//    private LedgerMaster incentiveLedger;
//
//    @ManyToOne
//    @JsonIgnoreProperties(value = {"attendance", "hibernateLazyInitializer"})
//    @JoinColumn(name = "late_punchin_id")
//    private LedgerMaster latePunchinLedger;

    @ManyToOne
    @JsonIgnoreProperties(value = {"attendance", "hibernateLazyInitializer"})
    @JoinColumn(name = "ledger_id", nullable = false)
    private LedgerMaster empLedger;

//    @OneToMany
//    @JsonIgnoreProperties(value = {"attendance", "hibernateLazyInitializer"})
//    @JoinColumn(name = "ledger_id", nullable = false)
    @OneToMany(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    private List<LedgerMaster> ledgers;

    private Double basic;
    private Double specialAllowance;
    private Double pf;
    private Double esi;
    private Double pfTax;
    private Double incentive;
    private Double latePunchIn;
    private Double netPayableAmount;
    private Double payableAmount;
    private String financialYear;
    private LocalDate createdAt;
    private LocalDate salaryMonth;
    private Boolean status;
    private Long createdBy;
    private LocalDate updatedAt;
    private Long updatedBy;
    private Boolean isSalaryProcessed;

    @ManyToOne
    @JoinColumn(name = "branch_id")
    @JsonManagedReference
    private Branch branch;

    @ManyToOne
    @JsonManagedReference
    @JoinColumn(name = "company_id")
    private Company company;

    @ManyToOne
    @JoinColumn(name = "fiscal_year_id")
    @JsonManagedReference
    private FiscalYear fiscalYear;

    @ManyToOne
    @JoinColumn(name = "associates_groups_id")
    @JsonManagedReference
    private AssociateGroups associateGroups;
}

package com.opethic.hrms.HRMSNew.models.report;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.opethic.hrms.HRMSNew.models.master.Branch;
import com.opethic.hrms.HRMSNew.models.master.Company;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "day_book_tbl")
public class DayBook {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private LocalDate tranxDate;
    private String particulars;//Ledger Name
    private String voucherNo;
    private String voucherType;
    private Double amount;

    @ManyToOne
    @JsonManagedReference
    @JoinColumn(name = "branch_id")
    private Branch branch;

    @ManyToOne
    @JsonManagedReference
    @JoinColumn(name = "company_id")
    private Company company;

    private Long createdBy;
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Boolean status;


}


package com.opethic.hrms.HRMSNew.models.master;


import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.opethic.hrms.HRMSNew.models.tranx.gstinput.GstInputDetails;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "tax_master_tbl")
public class TaxMaster {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String gst_per;
    private Double cgst;
    private Double sgst;
    private Double igst;
    private Double sratio; // sratio will be calculated automatically
    private LocalDate applicableDate;
    private Long createdBy;
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Boolean status;
    @UpdateTimestamp
    private LocalDateTime updatedAt;
    private Long updatedBy;

    @ManyToOne
    @JoinColumn(name = "branch_id")
    @JsonManagedReference
    private Branch branch;

    @ManyToOne
    @JoinColumn(name = "company_id")
    @JsonManagedReference
    private Company company;

    @JsonBackReference
    @OneToMany(fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private List<GstInputDetails> gstInputDetails;


}

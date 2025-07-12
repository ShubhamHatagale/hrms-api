package com.opethic.hrms.HRMSNew.models.tranx.gstouput;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.opethic.hrms.HRMSNew.models.master.TaxMaster;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.*;
import java.time.LocalDateTime;


@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "tranx_gst_ouput_details_tbl")
public class GstOutputDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "gst_ouput_id", nullable = false)
    @JsonManagedReference
    private GstOutputMaster gstOutputMaster;

    @ManyToOne
    @JoinColumn(name = "tax_id")
    @JsonManagedReference
    private TaxMaster taxMaster;
    private String particular;
    private String hsnNo;
    private Double igst;
    private Double cgst;
    private Double sgst;
    private Double amount;
    private Double qty;
    private Double finalAmt;
    private Double baseAmount;
    private Boolean status;
    private Long createdBy;
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Long updatedBy;
    @UpdateTimestamp
    private LocalDateTime updatedAt;

}

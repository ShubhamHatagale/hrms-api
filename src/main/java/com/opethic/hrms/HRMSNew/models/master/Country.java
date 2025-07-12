package com.opethic.hrms.HRMSNew.models.master;

import lombok.Data;

import javax.persistence.*;

@Data
@Entity
@Table(name = "country_tbl")
public class Country {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 150)
    private String name;
    private String phonecode;
    private String currency;
    private String currencySymbol;
}

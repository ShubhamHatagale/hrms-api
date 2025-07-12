package com.opethic.hrms.HRMSNew.models.master;

import lombok.Data;

import javax.persistence.*;

@Data
@Entity
@Table(name = "city_tbl")
public class City {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;
        @Column(nullable = false, length = 50)
        private String name;
        @Column(columnDefinition = "mediumint")
        private Long stateId;
        private String stateCode;
        @Column(columnDefinition = "mediumint")
        private Long countryId;
        @Column(length = 2, columnDefinition = "char")
        private String countryCode;
}

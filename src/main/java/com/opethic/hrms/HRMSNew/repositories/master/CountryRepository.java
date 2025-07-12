package com.opethic.hrms.HRMSNew.repositories.master;


import com.opethic.hrms.HRMSNew.models.master.Country;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CountryRepository extends JpaRepository<Country,Long> {
    Country findByName(String india);
}

package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.Company;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CompanyRepository extends JpaRepository<Company, Long> {
    Company findByCompanyNameIgnoreCaseAndStatus(String companyName, boolean b);

    Company findByIdAndStatus(Long companyId, boolean b);

    List<Company> findAllByStatus(boolean b);
}

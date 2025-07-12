package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.Department;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface DepartmentRepository extends JpaRepository<Department, Long> {

    List<Department> findAllByCompanyIdAndBranchIdAndStatus(Long companyId, Long branchId, boolean b);

    Department findByIdAndStatus(Long departmentId, boolean b);
}
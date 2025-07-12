package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByRoleNameAndStatus(String roleName, boolean b);

    Role findByIdAndStatus(long parseLong, boolean b);

    List<Role> findByCompanyIdAndStatus(Long companyId, boolean b);

    Role findRoleById(long userRole);

    List<Role> findByStatus(boolean b);
}

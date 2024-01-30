package com.alibaba.nacos.plugin.auth.impl.roles.rbac;

import com.alibaba.nacos.auth.config.AuthConfigs;
import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.config.server.model.Page;
import com.alibaba.nacos.core.utils.Loggers;
import com.alibaba.nacos.plugin.auth.api.Permission;
import com.alibaba.nacos.plugin.auth.api.Resource;
import com.alibaba.nacos.plugin.auth.constant.ActionTypes;
import com.alibaba.nacos.plugin.auth.constant.SignType;
import com.alibaba.nacos.plugin.auth.impl.constant.AuthConstants;
import com.alibaba.nacos.plugin.auth.impl.persistence.RoleInfo;
import com.alibaba.nacos.plugin.auth.impl.persistence.rbac.RbacRomePermissionInfo;
import com.alibaba.nacos.plugin.auth.impl.persistence.rbac.RbacRomePermissionPersistService;
import com.alibaba.nacos.plugin.auth.impl.roles.NacosRoleServiceImpl;
import io.jsonwebtoken.lang.Collections;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


/**
 * @author caoxingming
 * @name RbacRomeNacosRoleServiceImpl
 * @data 2023-03-31-3:03 PM
 * @description: 来伊份个性化权限service.
 */
@Service
public class RbacRomeNacosRoleServiceImpl {

    private static final int DEFAULT_PAGE_NO = 1;

    @Autowired
    private AuthConfigs authConfigs;

    @Autowired
    private NacosRoleServiceImpl nacosRoleService;

    @Autowired
    private RbacRomePermissionPersistService rbacRomePermissionPersistService;

    private volatile Map<String, List<RbacRomePermissionInfo>> romePermissionInfoMap = new ConcurrentHashMap<>();


    @Scheduled(initialDelay = 5000, fixedDelay = 15000)
    private void reload() {
        try {
            Page<RbacRomePermissionInfo> romePermissionInfoPage = rbacRomePermissionPersistService
                    .findRomePermissionByRoleAndDataid(StringUtils.EMPTY, StringUtils.EMPTY, DEFAULT_PAGE_NO, Integer.MAX_VALUE);
            if (romePermissionInfoPage == null) {
                return;
            }
            Map<String, List<RbacRomePermissionInfo>> tmpRomePermissionInfoMap = new ConcurrentHashMap<>(16);
            for (RbacRomePermissionInfo rbacRomePermissionInfo : romePermissionInfoPage.getPageItems()) {
                if (!tmpRomePermissionInfoMap.containsKey(rbacRomePermissionInfo.getRole())) {
                    tmpRomePermissionInfoMap.put(rbacRomePermissionInfo.getRole(), new ArrayList<>());
                }
                tmpRomePermissionInfoMap.get(rbacRomePermissionInfo.getRole()).add(rbacRomePermissionInfo);
            }

            romePermissionInfoMap = tmpRomePermissionInfoMap;
        } catch (Exception e) {
            Loggers.AUTH.warn("[LOAD-ROME-PERMISSION] load failed", e);
        }
    }

    /*
     * 判断用户是否具有响应的访问/操作权限
     * @param username
     * @param permission
     * @return
     */
    @SuppressWarnings("checkstyle:MissingJavadocMethod")
    public boolean hasPermission(String username, Permission permission) {
        //兼容 nacos 自带的权限验证体系
        if(!nacosRoleService.hasPermission(username, permission)) return false;

        //来伊份个性化的权限管理验证
        if(!this.romeUserHasPermission(username, permission)) return false;

        return true;
    }

    /*
     * 来伊份个性化权限验证
     * @param username
     * @param permission
     * @return
     */
    @SuppressWarnings("checkstyle:MissingJavadocMethod")
    public boolean romeUserHasPermission(String username, Permission permission) {
        if (AuthConstants.UPDATE_PASSWORD_ENTRY_POINT.equals(permission.getResource().getName())) {
            return true;
        }

        List<RoleInfo> roleInfoList = nacosRoleService.getRoles(username);

        if (Collections.isEmpty(roleInfoList)) {
            return false;
        }

        for (RoleInfo roleInfo : roleInfoList) {
            if (AuthConstants.GLOBAL_ADMIN_ROLE.equals(roleInfo.getRole())) {
                return true;
            }
            if (AuthConstants.REMOTE_READONLY_ROLE.equals(roleInfo.getRole()) && ActionTypes.READ.toString().equals(permission.getAction())) {
                return true;
            }
            if (AuthConstants.GLOBAL_READONLY_ROLE.equals(roleInfo.getRole()) && ActionTypes.READ.toString().equals(permission.getAction())) {
                return true;
            }
        }

        Resource resource = permission.getResource();
        if (!SignType.CONFIG.equals(resource.getType()))
            return true;
        if(StringUtils.isEmpty(resource.getName()))
            return true;
        for (RoleInfo roleInfo : roleInfoList) {
            List<RbacRomePermissionInfo> rbacRomePermissionInfoList = getRomePermissions(roleInfo.getRole());
            if (Collections.isEmpty(rbacRomePermissionInfoList)) {
                continue;
            }
            for (RbacRomePermissionInfo rbacRomePermissionInfo : rbacRomePermissionInfoList) {
                if(this.checkRomePermission(permission, rbacRomePermissionInfo))
                    return true;
            }
        }
        return false;
    }

    /*
     * 来伊份个性化权限验证(验证一批应用权限),如果存在无权限的应用则返回false, 如果全部应用都有权限则返回 true
     * @param username
     * @param permission
     * @return
     */
    @SuppressWarnings("checkstyle:MissingJavadocMethod")
    public boolean romeUserHasAllPermission(String username, List<Permission> permissions) {
        List<RoleInfo> roleInfoList = nacosRoleService.getRoles(username);

        if (Collections.isEmpty(roleInfoList)) {
            return false;
        }

        // Global admin pass:
        for (RoleInfo roleInfo : roleInfoList) {
            if (AuthConstants.GLOBAL_ADMIN_ROLE.equals(roleInfo.getRole())) {
                return true;
            }
            if (AuthConstants.GLOBAL_READONLY_ROLE.equals(roleInfo.getRole()) && permissions.stream().allMatch(b-> ActionTypes.READ.toString().equals(b.getAction()))) {
                return true;
            }
        }

        for (Permission permission: permissions) {
            for (RoleInfo roleInfo : roleInfoList) {
                List<RbacRomePermissionInfo> rbacRomePermissionInfoList = getRomePermissions(roleInfo.getRole());
                if (Collections.isEmpty(rbacRomePermissionInfoList)) {
                    continue;
                }
                for (RbacRomePermissionInfo rbacRomePermissionInfo : rbacRomePermissionInfoList) {
                    if(!this.checkRomePermission(permission, rbacRomePermissionInfo))
                        return false;
                }
            }
        }
        return true;
    }



    /***
     * 检查用户行为 是否 通过罗马权限校验
     * @param permission
     * @param rbacRomePermissionInfo
     * @return
     */
    private boolean checkRomePermission(Permission permission, RbacRomePermissionInfo rbacRomePermissionInfo) {
        Resource resource = permission.getResource();
        //如果是模糊匹配,默认给与权限
        if(resource.getName().startsWith("*") && resource.getName().endsWith("*")) return true;

        if(!StringUtils.equals(resource.getName(), rbacRomePermissionInfo.getDataId()))  return false;
        if(StringUtils.isNotEmpty(rbacRomePermissionInfo.getAction()) && rbacRomePermissionInfo.getAction().contains(permission.getAction())) return true;
        return false;
    }


    /***
     * 根据 role 获取 role 对应的权限 infos.
     * @param role
     * @return
     */
    public List<RbacRomePermissionInfo> getRomePermissions(String role) {
        List<RbacRomePermissionInfo> rbacRomePermissionInfoList = romePermissionInfoMap.get(role);
        if (!authConfigs.isCachingEnabled() || rbacRomePermissionInfoList == null) {
            Page<RbacRomePermissionInfo> permissionInfoPage = getRomePermissionsFromDatabase( role, StringUtils.EMPTY, DEFAULT_PAGE_NO,
                    Integer.MAX_VALUE);
            if (rbacRomePermissionInfoList != null) {
                rbacRomePermissionInfoList = permissionInfoPage.getPageItems();
                if (!Collections.isEmpty(rbacRomePermissionInfoList)) {
                    romePermissionInfoMap.put(role, rbacRomePermissionInfoList);
                }
            }
        }
        return rbacRomePermissionInfoList;
    }

    /***
     * 根据 role,dataid,分页数据 分页获取对应的权限 infos.
     * @param role
     * @param dataid
     * @param pageNo
     * @param pageSize
     * @return
     */
    private Page<RbacRomePermissionInfo> getRomePermissionsFromDatabase(String role, String dataid, int pageNo, int pageSize) {
        Page<RbacRomePermissionInfo> romePermissionInfoPage = rbacRomePermissionPersistService.findRomePermissionByRoleAndDataid(role, dataid, pageNo, pageSize);
        if (romePermissionInfoPage == null) {
            return new Page<>();
        }
        return romePermissionInfoPage;
    }

}

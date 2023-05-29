package com.alibaba.nacos.plugin.auth.impl.roles;

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
import com.alibaba.nacos.plugin.auth.impl.persistence.RomePermissionInfo;
import com.alibaba.nacos.plugin.auth.impl.persistence.RomePermissionPersistService;
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
 * @name RomeNacosRoleServiceImpl
 * @data 2023-03-31-3:03 PM
 * @description: 来伊份个性化权限service.
 */
@Service
public class RomeNacosRoleServiceImpl {

    private static final int DEFAULT_PAGE_NO = 1;

    @Autowired
    private AuthConfigs authConfigs;

    @Autowired
    private NacosRoleServiceImpl nacosRoleService;

    @Autowired
    private RomePermissionPersistService romePermissionPersistService;

    private volatile Map<String, List<RomePermissionInfo>> romePermissionInfoMap = new ConcurrentHashMap<>();


    @Scheduled(initialDelay = 5000, fixedDelay = 15000)
    private void reload() {
        try {
            Page<RomePermissionInfo> romePermissionInfoPage = romePermissionPersistService
                    .findRomePermissionByRoleAndDataid(StringUtils.EMPTY, StringUtils.EMPTY, DEFAULT_PAGE_NO, Integer.MAX_VALUE);
            if (romePermissionInfoPage == null) {
                return;
            }
            Map<String, List<RomePermissionInfo>> tmpRomePermissionInfoMap = new ConcurrentHashMap<>(16);
            for (RomePermissionInfo romePermissionInfo : romePermissionInfoPage.getPageItems()) {
                if (!tmpRomePermissionInfoMap.containsKey(romePermissionInfo.getRole())) {
                    tmpRomePermissionInfoMap.put(romePermissionInfo.getRole(), new ArrayList<>());
                }
                tmpRomePermissionInfoMap.get(romePermissionInfo.getRole()).add(romePermissionInfo);
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

        Resource resource = permission.getResource();
        if (!SignType.CONFIG.equals(resource.getType()))
            return true;
        if(StringUtils.isEmpty(resource.getName()))
            return true;
        for (RoleInfo roleInfo : roleInfoList) {
            List<RomePermissionInfo> romePermissionInfoList = getRomePermissions(roleInfo.getRole());
            if (Collections.isEmpty(romePermissionInfoList)) {
                continue;
            }
            for (RomePermissionInfo romePermissionInfo : romePermissionInfoList) {
                if(this.checkRomePermission(permission,romePermissionInfo))
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
        }

        for (Permission permission: permissions) {
            for (RoleInfo roleInfo : roleInfoList) {
                List<RomePermissionInfo> romePermissionInfoList = getRomePermissions(roleInfo.getRole());
                if (Collections.isEmpty(romePermissionInfoList)) {
                    continue;
                }
                for (RomePermissionInfo romePermissionInfo : romePermissionInfoList) {
                    if(!this.checkRomePermission(permission,romePermissionInfo))
                        return false;
                }
            }
        }
        return true;
    }



    /***
     * 检查用户行为 是否 通过罗马权限校验
     * @param permission
     * @param romePermissionInfo
     * @return
     */
    private boolean checkRomePermission(Permission permission, RomePermissionInfo romePermissionInfo) {
        Resource resource = permission.getResource();
        //如果是模糊匹配,默认给与权限
        if(resource.getName().startsWith("*") && resource.getName().endsWith("*")) return true;

        if(!StringUtils.equals(resource.getName(),romePermissionInfo.getDataId()))  return false;
        if(StringUtils.isNotEmpty(romePermissionInfo.getAction()) && romePermissionInfo.getAction().contains(permission.getAction())) return true;
        return false;
    }


    /***
     * 根据 role 获取 role 对应的权限 infos.
     * @param role
     * @return
     */
    public List<RomePermissionInfo> getRomePermissions(String role) {
        List<RomePermissionInfo> romePermissionInfoList = romePermissionInfoMap.get(role);
        if (!authConfigs.isCachingEnabled() || romePermissionInfoList == null) {
            Page<RomePermissionInfo> permissionInfoPage = getRomePermissionsFromDatabase( role, StringUtils.EMPTY, DEFAULT_PAGE_NO,
                    Integer.MAX_VALUE);
            if (romePermissionInfoList != null) {
                romePermissionInfoList = permissionInfoPage.getPageItems();
                if (!Collections.isEmpty(romePermissionInfoList)) {
                    romePermissionInfoMap.put(role, romePermissionInfoList);
                }
            }
        }
        return romePermissionInfoList;
    }

    /***
     * 根据 role,dataid,分页数据 分页获取对应的权限 infos.
     * @param role
     * @param dataid
     * @param pageNo
     * @param pageSize
     * @return
     */
    private Page<RomePermissionInfo> getRomePermissionsFromDatabase(String role, String dataid, int pageNo, int pageSize) {
        Page<RomePermissionInfo> romePermissionInfoPage = romePermissionPersistService.findRomePermissionByRoleAndDataid(role, dataid, pageNo, pageSize);
        if (romePermissionInfoPage == null) {
            return new Page<>();
        }
        return romePermissionInfoPage;
    }

}

package com.alibaba.nacos.plugin.auth.impl.persistence;

import java.io.Serializable;

/**
 * @author caoxingming
 * @name RomePermissionInfo
 * @data 2023-03-31-4:17 PM
 * @description: 来伊份权限实体
 */
public class RomePermissionInfo implements Serializable {

    private static final long serialVersionUID = 388813673388837395L;


    /***
     * role
     */
    private String role;


    /***
     * 配置 dataid
     */
    private String dataId;


    /**
     * Action on resource.
     */
    private String action;

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getDataId() {
        return dataId;
    }

    public void setDataId(String dataId) {
        this.dataId = dataId;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }
}

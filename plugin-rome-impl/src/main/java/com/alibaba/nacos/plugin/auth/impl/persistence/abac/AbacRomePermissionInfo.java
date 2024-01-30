package com.alibaba.nacos.plugin.auth.impl.persistence.abac;

import java.io.Serializable;

/**
 * @author caoxingming
 * @name AbacRomePermissionInfo
 * @data 2023-03-31-4:17 PM
 * @description: 罗马abac权限Info类
 */
public class AbacRomePermissionInfo implements Serializable {

    private static final long serialVersionUID = 388813673388837395L;

    /***
     * 用户名
     */
    private String username;

    /***
     * 配置 dataid
     */
    private String dataId;


    /**
     * Action on resource.
     */
    private String action;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
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

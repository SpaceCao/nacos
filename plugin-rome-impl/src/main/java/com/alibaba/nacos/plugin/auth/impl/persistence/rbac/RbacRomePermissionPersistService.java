/*
 * Copyright 1999-2021 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.nacos.plugin.auth.impl.persistence.rbac;

import com.alibaba.nacos.config.server.model.Page;

/**
  * @author: caoxingming
  * @data: 2023/3/31 4:14 PM
  * @description: 来伊份个性化权限持久层
  **/
@SuppressWarnings("PMD.AbstractMethodOrInterfaceMethodMustUseJavadocRule")
public interface RbacRomePermissionPersistService {


    /***
     * 根据 role 和 dataid 分页获取来伊份个性化权限信息
     * @param role
     * @param dataid
     * @return
     */
    Page<RbacRomePermissionInfo> findRomePermissionByRoleAndDataid(String role, String dataid, int pageNo, int pageSize);
}

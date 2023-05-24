/*
 * Copyright 1999-2018 Alibaba Group Holding Ltd.
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

package com.alibaba.nacos.plugin.auth.impl.result.code;

import com.alibaba.nacos.common.model.core.IResultCode;

/**
 * ResultCodeEnum.
 *
 * @author klw
 * @ClassName: ResultCodeEnum
 * @Description: result code enum
 * @date 2019/6/28 14:43
 */
public enum RomeResultCodeEnum implements IResultCode {


    INSUFFICIENT_PERMISSION_CONFIG(100007, "操作权限不足");

    private int code;

    private String msg;

    RomeResultCodeEnum(int code, String codeMsg) {
        this.code = code;
        this.msg = codeMsg;
    }
    
    @Override
    public int getCode() {
        return code;
    }
    
    @Override
    public String getCodeMsg() {
        return msg;
    }
}

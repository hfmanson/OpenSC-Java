/***********************************************************
 * $Id$
 * 
 * PKCS#15 cryptographic provider of the opensc project.
 * http://www.opensc-project.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Created: 31.12.2007
 * 
 ***********************************************************/

package org.opensc.pkcs15.asn1;

import org.opensc.pkcs15.asn1.attr.CommonKeyAttributes;

/**
 * This interface is implemented by all private and public key objects.
 * 
 * @author wglas
 */
public interface PKCS15Key extends PKCS15Object {

    /**
     * @return the commonKeyAttributes
     */
    public CommonKeyAttributes getCommonKeyAttributes();

    /**
     * @param commonKeyAttributes the commonKeyAttributes to set
     */
    public void setCommonKeyAttributes(CommonKeyAttributes commonKeyAttributes);
}
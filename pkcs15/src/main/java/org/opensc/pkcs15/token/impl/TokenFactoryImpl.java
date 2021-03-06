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
 * Created: 26.12.2007
 *
 ***********************************************************/

package org.opensc.pkcs15.token.impl;

import java.io.File;
import java.io.IOException;

import javax.smartcardio.ATR;
import javax.smartcardio.Card;

import org.opensc.pkcs15.token.Token;
import org.opensc.pkcs15.token.TokenFactory;
import org.opensc.pkcs15.util.Util;

/**
 * @author wglas
 *
 */
public class TokenFactoryImpl extends TokenFactory {

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.TokenFactory#newHardwareToken(javax.smartcardio.Card)
     */
    @Override
    public Token newHardwareToken(Card card) throws IOException {

        ATR atr = card.getATR();

        if (CardOSToken.CARDOS_4_3_b_ATR.equals(atr))
            return new CardOSToken(card.getBasicChannel());

        if (IsoAppletToken.ISOAPPLET_ATR.equals(atr))
            return new IsoAppletToken(card.getBasicChannel());

        throw new IOException("Card has an unrecognized ATR ["+Util.asHex(atr.getBytes())+"].");
    }

    /* (non-Javadoc)
     * @see org.opensc.pkcs15.token.TokenFactory#newSoftwareToken(java.io.File)
     */
    @Override
    public Token newSoftwareToken(File file) throws IOException {

        return new SoftwareToken(file);
    }

}

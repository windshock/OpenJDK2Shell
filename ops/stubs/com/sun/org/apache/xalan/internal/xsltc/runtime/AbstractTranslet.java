package com.sun.org.apache.xalan.internal.xsltc.runtime;
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
public abstract class AbstractTranslet {
    public abstract void transform(DOM d, DTMAxisIterator i, SerializationHandler h);
    public abstract void transform(DOM d, SerializationHandler[] h);
}

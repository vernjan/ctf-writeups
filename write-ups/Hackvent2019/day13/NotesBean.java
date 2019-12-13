package com.jwt.jsf.bean;
import org.apache.commons.collections4.trie.PatriciaTrie;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.io.StringWriter;

import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import static org.apache.commons.lang3.StringEscapeUtils.unescapeJava;
import org.apache.commons.io.IOUtils;

@ManagedBean(name="notesBean")
@SessionScoped
public class NotesBean implements Serializable {

	/**
	 * 
	 */
	private PatriciaTrie<Integer> trie = init();
	private static final long serialVersionUID = 1L;
	private static final String securitytoken = "auth_token_4835989";

	public NotesBean() {
	    super();
	    init();
	}

	public String getTrie() throws IOException {
		if(isAdmin(trie)) {
			InputStream in=getStreamFromResourcesFolder("data/flag.txt");
			StringWriter writer = new StringWriter();
			IOUtils.copy(in, writer, "UTF-8");
			String flag = writer.toString();

			return flag;
		}
		return "INTRUSION WILL BE REPORTED!";
	}

	public void setTrie(String note) {
		trie.put(unescapeJava(note), 0);
	}
		
    private static PatriciaTrie<Integer> init(){
        PatriciaTrie<Integer> trie = new PatriciaTrie<Integer>();
        trie.put(securitytoken,0);

        return trie;
    }

    private static boolean isAdmin(PatriciaTrie<Integer> trie){
        return !trie.containsKey(securitytoken);
    }

    private static InputStream getStreamFromResourcesFolder(String filePath) {
    	  return Thread.currentThread().getContextClassLoader().getResourceAsStream(filePath);
    	 }

}

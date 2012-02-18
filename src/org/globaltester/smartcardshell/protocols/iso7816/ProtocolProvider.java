package org.globaltester.smartcardshell.protocols.iso7816;

import java.util.List;

import org.globaltester.smartcardshell.protocols.AbstractScshProtocolProvider;
import org.globaltester.smartcardshell.protocols.ScshCommand;
import org.globaltester.smartcardshell.protocols.ScshCommandParameter;


public class ProtocolProvider extends AbstractScshProtocolProvider {

	private static ScshCommand getChallenge;
	{
		getChallenge = new ScshCommand("getChallenge");
		getChallenge.setHelp("Send a GetChallenge APDU to the card");
		getChallenge.setHelpReturn("Challenge returned by card as ByteString");

		ScshCommandParameter leParam = new ScshCommandParameter("lengthExpected");
		leParam.setHelp("Integer describing the expected length of the challenge, defaults to 8 if not present (this will be encoded as Le field in the APDU)");
		getChallenge.addParam(leParam);

		String impl = "";
		impl += "if (lengthExpected == undefined) lengthExpected = 8;\n";
		impl += "\n";
		impl += "var cmd = this.gt_ISO7816_buildAPDU(0x00, 0x84, 0x00, 0x00, undefined, lengthExpected);\n"; 
		impl += "\n";
		impl += "var challenge = this.gt_sendCommand(cmd);\n";
		impl += "assertStatusWord(SW_NoError, card.SW.toString(HEX));\n";
		impl += "\n";
		impl += "return challenge\n";
		getChallenge.setImplementation(impl);
	}
	
	private static ScshCommand mutualAuthenticate;
	{
		mutualAuthenticate = new ScshCommand("mutualAuthenticate");
		mutualAuthenticate.setHelp("Send a MutualAuthenticte APDU to the card");
		mutualAuthenticate.setHelpReturn("Authentication related data returned by card as ByteString");

		ScshCommandParameter dataParam = new ScshCommandParameter("commandData");
		dataParam.setHelp("ByteString containing the authentication related data to be transmitted to the card, if not present the command will have no data field (this will be encoded as command data field in the APDU)");
		mutualAuthenticate.addParam(dataParam);
		
		ScshCommandParameter leParam = new ScshCommandParameter("lengthExpected");
		leParam.setHelp("Integer describing the expected length of the returned authentication data, defaults to length of input if not present (this will be encoded as Le field in the APDU)");
		mutualAuthenticate.addParam(leParam);

		String impl = "";
		impl += "if ((lengthExpected == undefined) && (commandData instanceof ByteString)) lengthExpected = commandData.length;\n";
		impl += "\n";
		impl += "var cmd = this.gt_ISO7816_buildAPDU(0x00, 0x82, 0x00, 0x00, commandData, lengthExpected);\n"; 
		impl += "\n";
		impl += "var challenge = this.gt_sendCommand(cmd);\n";
		impl += "assertStatusWord(SW_NoError, card.SW.toString(HEX));\n";
		impl += "\n";
		impl += "return challenge\n";
		mutualAuthenticate.setImplementation(impl);
	}
	
	private static ScshCommand buildAPDU;
	{
		buildAPDU = new ScshCommand("buildAPDU");
		buildAPDU.setHelp("Construct a valid APDU from the given parameter");
		buildAPDU.setHelpReturn("constructed APDU as ByteString");

		ScshCommandParameter claParam = new ScshCommandParameter("cla");
		claParam.setHelp("Integer used as CLA byte of the APDU");
		buildAPDU.addParam(claParam);
		
		ScshCommandParameter insParam = new ScshCommandParameter("ins");
		insParam.setHelp("Integer used as INS byte of the APDU");
		buildAPDU.addParam(insParam);
		
		ScshCommandParameter p1Param = new ScshCommandParameter("p1");
		p1Param.setHelp("Integer used as P1 byte of the APDU");
		buildAPDU.addParam(p1Param);
		
		ScshCommandParameter p2Param = new ScshCommandParameter("p2");
		p2Param.setHelp("Integer used as P2 byte of the APDU");
		buildAPDU.addParam(p2Param);
		
		ScshCommandParameter dataParam = new ScshCommandParameter("data");
		dataParam.setHelp("ByteString containing the command datafield, if not present the command will have no data field");
		buildAPDU.addParam(dataParam);
		
		ScshCommandParameter leParam = new ScshCommandParameter("le");
		leParam.setHelp("Integer from which Le will be constructed, 256 will be encoded as 00 in short format, 65536 will be ancoded as 0000 in extended length format, if parameter is absent the command APDU will not contain an Le field");
		buildAPDU.addParam(leParam);

		String impl = "";
		impl += "var cmd = HexString.hexifyByte(cla);\n";
		impl += "cmd = cmd.concat(HexString.hexifyByte(ins));\n";
		impl += "cmd = cmd.concat(HexString.hexifyByte(p1));\n";
		impl += "cmd = cmd.concat(HexString.hexifyByte(p2));\n";
		impl += "\n";
		//FIXME handle extendedLength
		impl += "if (data) {\n";
		impl += "    cmd = cmd.concat(HexString.hexifyByte(data.length));\n";
		impl += "    cmd = cmd.concat(data.toString(HEX));\n";
		impl += "}\n";
		impl += "if (le) {\n";
		impl += "    cmd = cmd.concat(HexString.hexifyByte(le));\n";
		impl += "}\n";
		impl += "\n";
		impl += "return new ByteString(cmd, HEX);\n";
		buildAPDU.setImplementation(impl);
	}
	
	private static ScshCommand selectAID;
	{
		selectAID = new ScshCommand("selectAID");
		selectAID.setHelp("Select the card application with the given ID and return FCI as ByteString");
		selectAID.setHelpReturn("file control information (fci) of selected application as ByteString");
		
		ScshCommandParameter aidParam = new ScshCommandParameter("aid");
		aidParam.setHelp("AID to select as String or ByteString");
		selectAID.addParam(aidParam);
		
		String impl = "";
		impl += "if (!(aid instanceof ByteString)) aid = new ByteString(aid,HEX);\n";
		impl += "var cmd = new ByteString(\"00 A4 04 00\", HEX);\n";
		impl += "    cmd = cmd.concat(new ByteString(HexString.hexifyByte(aid.length),HEX));\n";
		impl += "    cmd = cmd.concat(new ByteString(aid,HEX));\n";
		impl += "    cmd = cmd.concat(new ByteString(\"00\",HEX));\n";
		impl += "var fci = card.gt_sendCommand(cmd);\n";
		impl += "assertStatusWord(SW_NoError, card.SW.toString(HEX));\n";
		impl += "return fci;\n";
		selectAID.setImplementation(impl);
	}
	
	
	private static ScshCommand readBinary;
	{
		readBinary = new ScshCommand("readBinary");
		readBinary.setHelp("Send read binary with offset and le as Integer");
		readBinary.setHelpReturn("file data as ByteString");
		
		ScshCommandParameter offsetParam = new ScshCommandParameter("offset");
		offsetParam.setHelp("Integer as offset");
		readBinary.addParam(offsetParam);
		
		ScshCommandParameter leParam = new ScshCommandParameter("le");
		leParam.setHelp("Integer from which Le will be constructed, 256 will be encoded as 00 in short format, 65536 will be ancoded as 0000 in extended length format, if parameter is absent the command APDU will not contain an Le field");
		readBinary.addParam(leParam);
		
		String impl = "";

		impl += "if (offset instanceof String) \n";
		impl += "if (offset instanceof ByteString) offset = HexString.hexifyShort(offset);\n";

		impl += "print(\"Offset = \"+offset);\n";
		impl += "print(\"Length = \"+le);\n";
		
		impl += "if (le > 255) {print(\"LE byte to big! Set LE to: 0x00 \"); le = 0;}\n";
		impl += "if (offset > 32767) {print(\"Offset byte too big! Set Offset to: 0x7FFF \"); offset = 32767;}\n";
		impl += "var cmd = new ByteString(\"00 B0\", HEX);\n";
		impl += "if (le <= 255) {\n";
		impl += "	if (offset <= 255) {\n";
		impl += "		cmd = cmd.concat(new ByteString(\"00\",HEX));\n";
		impl += "		cmd = cmd.concat(new ByteString(HexString.hexifyByte(offset),HEX));\n";
		impl += "	}\n";
		impl += "	else\n";
		impl += "	{\n";
		impl += "		cmd = cmd.concat(new ByteString(HexString.hexifyShort(offset),HEX));\n";
		impl += "	}\n";
		impl += "}\n";
		impl += "	cmd = cmd.concat(new ByteString(HexString.hexifyByte(le),HEX));\n";
		impl += "\n";
		impl += "var rdata = card.gt_sendCommand(cmd);\n";
		impl += "assertStatusWord(SW_NoError, card.SW.toString(HEX));\n";
		impl += "return rdata;\n";
		readBinary.setImplementation(impl);
	}
	
	private static ScshCommand selectFile;
	{
		selectFile = new ScshCommand("selectFile");
		selectFile.setHelp("Send select file with file identifier");
		
		ScshCommandParameter fidParam = new ScshCommandParameter("fileIdentifier");
		fidParam.setHelp("file identifier with one or two bytes as String or ByteString");
		selectFile.addParam(fidParam);
		
		String impl = "";
		impl += "	if (!(fileIdentifier instanceof ByteString)) fileIdentifier = new ByteString(fileIdentifier,HEX);\n";
		impl += "var cmd = new ByteString(\"00 A4 02 0C 02\", HEX);\n";
		impl += "if (fileIdentifier.length <= 2) {\n";
		impl += "    cmd = cmd.concat(new ByteString(\"01\",HEX));\n";
		impl += "    cmd = cmd.concat(new ByteString(fileIdentifier,HEX));\n";
		impl += "}\n";
		impl += "else \n";
		impl += "{\n";
		impl += "    cmd = cmd.concat(new ByteString(fileIdentifier,HEX));\n";
		impl += "}\n";
		impl += "\n";
		impl += "card.gt_sendCommand(cmd);\n";
		impl += "assertStatusWord(SW_NoError, card.SW.toString(HEX));\n";
		selectFile.setImplementation(impl);
	}
	
	private static ScshCommand readFile;
	{
		
		readFile = new ScshCommand("readFile");
		readFile.setHelp("Send read file with fileIdentifier ID");
		readFile.setHelpReturn("file data returned by card as ByteString");
		
		ScshCommandParameter fidParam = new ScshCommandParameter("fileIdentifier");
		fidParam.setHelp("file Identifier with one byte as String or ByteString");
		readFile.addParam(fidParam);
		
		String impl = "";
		impl += "if (!(fileIdentifier instanceof ByteString)) fileIdentifier = new ByteString(fileIdentifier,HEX);\n";
		impl += "this.gt_ISO7816_selectFile(fileIdentifier);\n";
		impl += "var header = this.gt_ISO7816_readBinary(0, 4);\n";
		impl += "print(\"File Header: \"+header);\n";
		impl += "var fileLength = checkLengthEncoding(header.bytes(1,3));\n";
		impl += "print(\"Encoded File Length: \"+fileLength +\" bytes\");\n";
		impl += "fileLength = fileLength + 1 +getSizeHelper(fileLength);\n";
		impl += "offset = 0;\n";

		// Maybe set other values in future
		impl += "var _readBuffer = 223;\n";
		impl += "var blocksize = 223;\n";

		impl += "var rsp = new ByteString(\"\", HEX);\n";
		impl += "if (_readBuffer == 0){\n";
		impl += "while (offset < fileLength) {\n";
		impl += "		var tmp = this.gt_ISO7816_readBinary(offset, 255);\n";
		impl += "		rsp = rsp.concat(tmp);\n";
		impl += "		offset = offset + tmp.length;\n";
		impl += "		print(\"Read \" + rsp.length + \" of \" + fileLength + \" bytes.\");\n";
		impl += "}\n";
		impl += "} else {\n";
		impl += "	if (fileLength > blocksize) {\n";
		impl += "		while (offset < fileLength - blocksize) {\n";
		impl += "			tmp = this.gt_ISO7816_readBinary(offset, blocksize);\n";
		impl += "			rsp = rsp.concat(tmp);\n";
		impl += "			offset = offset + tmp.length;\n";
		impl += "			print(\"Read \" + rsp.length + \" of \" + fileLength + \" bytes.\");\n";
		impl += "		}\n";
		impl += "		tmp = this.gt_ISO7816_readBinary(offset, fileLength - offset);\n";
		impl += "		rsp = rsp.concat(tmp);\n";
		impl += "		offset = offset + tmp.length;\n";
		impl += "		print(\"Read \" + rsp.length + \" of \" + fileLength + \" bytes.\");\n";
		impl += "	}\n";
		impl += "	else {\n";
		impl += "		tmp = this.gt_ISO7816_readBinary(0, fileLength);\n";
		impl += "		rsp = rsp.concat(tmp);\n";
		impl += "		offset = offset + tmp.length;\n";
		impl += "		print(\"Read \" + rsp.length + \" of \" + fileLength + \" bytes.\");\n";
		impl += "	}\n";
		impl += "}\n";	
		impl += "return rsp;\n";	
		readFile.setImplementation(impl);
	}

	
	@Override
	public void addCommands(List<ScshCommand> commandList) {
		commandList.add(buildAPDU);
		commandList.add(getChallenge);
		commandList.add(mutualAuthenticate);
		commandList.add(selectAID);
		commandList.add(readBinary);
		commandList.add(selectFile);
		commandList.add(readFile);
	}

}

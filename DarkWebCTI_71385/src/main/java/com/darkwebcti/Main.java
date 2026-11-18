package com.darkwebcti;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.*;
import java.time.format.*;
import java.util.*;
import java.util.List;
import java.util.regex.*;

/**
 * Dark Web Cyber Threat Intelligence Analysis - standalone educational CSV analyser.
 * Workflow: select a CSV first, then click Analyse Data.
 */
public class Main extends JFrame {
    private final Color navy = new Color(19, 32, 53), blue = new Color(30, 105, 165), bg = new Color(244,247,251);
    private final List<ThreatRecord> records = new ArrayList<>();
    private final List<ThreatRecord> analysed = new ArrayList<>();
    private File selectedFile;
    private String datasetName = "No dataset selected";
    private JLabel fileLabel, statusLabel;
    private JButton analyseButton;
    private JLabel totalValue, highValue, mediumValue, lowValue, iocValue, missingValue;
    private JTextArea overview, reportArea, iocArea;
    private DefaultTableModel tableModel;
    private JTable table;
    private JPanel dashboardPanel;
    private ChartPanel categoryChart, monthlyChart;
    private JTabbedPane tabs;

    public Main() {
        super("Dark Web Cyber Threat Intelligence Analysis");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(1120, 760));
        setSize(1320, 850);
        setLocationRelativeTo(null);
        getContentPane().setBackground(bg);
        setLayout(new BorderLayout());
        add(buildHeader(), BorderLayout.NORTH);
        tabs = new JTabbedPane();
        tabs.addTab("Dashboard", buildDashboard());
        tabs.addTab("Dataset Records", buildRecords());
        tabs.addTab("IOC Extraction", buildIoc());
        tabs.addTab("Analysis Report", buildReportPanel());
        tabs.setFont(new Font("SansSerif", Font.BOLD, 13));
        add(tabs, BorderLayout.CENTER);
        showEmptyState();
    }

    private JPanel buildHeader() {
        JPanel outer = new JPanel(new BorderLayout(16, 10));
        outer.setBackground(navy); outer.setBorder(new EmptyBorder(18, 22, 16, 22));
        JPanel text = new JPanel(new GridLayout(2,1,0,5)); text.setOpaque(false);
        JLabel title = new JLabel("DARK WEB  /  CYBER THREAT INTELLIGENCE");
        title.setForeground(Color.WHITE); title.setFont(new Font("SansSerif", Font.BOLD, 21));
        JLabel sub = new JLabel("Dataset exploration  •  Threat classification  •  Indicator extraction  •  Reporting");
        sub.setForeground(new Color(190,205,225)); sub.setFont(new Font("SansSerif", Font.PLAIN, 12));
        text.add(title); text.add(sub); outer.add(text, BorderLayout.WEST);

        JPanel actions = new JPanel(new GridLayout(2,1,0,7)); actions.setOpaque(false);
        JButton select = new JButton("1. Select CSV Dataset"); styleButton(select, new Color(232,240,248), navy);
        select.addActionListener(e -> chooseDataset());
        analyseButton = new JButton("2. Analyse Data"); styleButton(analyseButton, new Color(36,137,199), Color.WHITE);
        analyseButton.setEnabled(false); analyseButton.addActionListener(e -> analyseDataset());
        actions.add(select); actions.add(analyseButton); outer.add(actions, BorderLayout.EAST);
        JPanel bottom = new JPanel(new BorderLayout()); bottom.setOpaque(false);
        fileLabel = new JLabel("Selected file: none"); fileLabel.setForeground(Color.WHITE);
        statusLabel = new JLabel("Step 1: Select a CSV dataset to begin"); statusLabel.setForeground(new Color(255,215,135));
        bottom.add(fileLabel, BorderLayout.WEST); bottom.add(statusLabel, BorderLayout.EAST);
        outer.add(bottom, BorderLayout.SOUTH);
        return outer;
    }

    private JPanel buildDashboard() {
        dashboardPanel = new JPanel(new BorderLayout(14,14)); dashboardPanel.setBackground(bg); dashboardPanel.setBorder(new EmptyBorder(16,16,16,16));
        JPanel cards = new JPanel(new GridLayout(1,6,10,10)); cards.setOpaque(false);
        totalValue = metric(); highValue = metric(); mediumValue = metric(); lowValue = metric(); iocValue = metric(); missingValue = metric();
        cards.add(metricCard("TOTAL RECORDS", totalValue)); cards.add(metricCard("HIGH RISK", highValue));
        cards.add(metricCard("MEDIUM RISK", mediumValue)); cards.add(metricCard("LOW RISK", lowValue));
        cards.add(metricCard("IOC MATCHES", iocValue)); cards.add(metricCard("MISSING CATEGORY", missingValue));
        dashboardPanel.add(cards, BorderLayout.NORTH);
        JPanel charts = new JPanel(new GridLayout(1,2,14,14)); charts.setOpaque(false);
        categoryChart = new ChartPanel("Threat category distribution", false);
        monthlyChart = new ChartPanel("Monthly record activity", true);
        charts.add(chartBox(categoryChart)); charts.add(chartBox(monthlyChart));
        JPanel lower = new JPanel(new GridLayout(1,2,14,14)); lower.setOpaque(false);
        overview = new JTextArea(); overview.setEditable(false); overview.setFont(new Font("SansSerif",0,14)); overview.setMargin(new Insets(12,12,12,12)); overview.setLineWrap(true); overview.setWrapStyleWord(true);
        lower.add(wrapPanel("Dataset overview", new JScrollPane(overview)));
        JTextArea guidance = new JTextArea("HOW TO USE THIS ANALYSIS\n\n1. Select a CSV file using the button above.\n2. Confirm the selected file name.\n3. Click Analyse Data.\n4. Review the dashboard, records, IOCs and report.\n\nRisk scores are rule-based indicators for academic exploration. They are not proof of malicious activity. Review findings before drawing conclusions.");
        guidance.setEditable(false); guidance.setFont(new Font("SansSerif",0,14)); guidance.setMargin(new Insets(12,12,12,12)); guidance.setLineWrap(true); guidance.setWrapStyleWord(true);
        lower.add(wrapPanel("Getting started & interpretation", new JScrollPane(guidance)));
        JPanel center = new JPanel(new BorderLayout(12,12)); center.setOpaque(false); center.add(charts,BorderLayout.CENTER); center.add(lower,BorderLayout.SOUTH);
        dashboardPanel.add(center,BorderLayout.CENTER);
        return dashboardPanel;
    }

    private JPanel buildRecords() {
        JPanel p = new JPanel(new BorderLayout(8,8)); p.setBackground(bg); p.setBorder(new EmptyBorder(14,14,14,14));
        JPanel top = new JPanel(new BorderLayout(8,8)); top.setOpaque(false);
        JTextField search = new JTextField(); search.setToolTipText("Search title, text, category or risk");
        JButton find = new JButton("Search"); find.addActionListener(e -> filterTable(search.getText()));
        JButton reset = new JButton("Show all"); reset.addActionListener(e -> populateTable(analysed));
        top.add(new JLabel("Search records: "),BorderLayout.WEST); top.add(search,BorderLayout.CENTER);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT,5,0)); buttons.setOpaque(false); buttons.add(find); buttons.add(reset); top.add(buttons,BorderLayout.EAST);
        p.add(top,BorderLayout.NORTH);
        tableModel = new DefaultTableModel(new Object[]{"ID", "Date", "Category", "Threat Type", "Risk", "Score", "Text / Content"},0) { public boolean isCellEditable(int r,int c){return false;} };
        table = new JTable(tableModel); table.setRowHeight(25); table.setAutoCreateRowSorter(true); table.setFillsViewportHeight(true);
        table.getColumnModel().getColumn(6).setPreferredWidth(520); p.add(new JScrollPane(table),BorderLayout.CENTER);
        return p;
    }

    private JPanel buildIoc() {
        JPanel p = new JPanel(new BorderLayout(10,10)); p.setBackground(bg); p.setBorder(new EmptyBorder(16,16,16,16));
        iocArea = new JTextArea("Select a dataset and click Analyse Data to extract indicators."); iocArea.setEditable(false); iocArea.setFont(new Font(Font.MONOSPACED,0,13));
        JButton export = new JButton("Export IOC list (CSV)"); export.addActionListener(e -> exportIocs());
        p.add(export,BorderLayout.NORTH); p.add(new JScrollPane(iocArea),BorderLayout.CENTER); return p;
    }

    private JPanel buildReportPanel() {
        JPanel p = new JPanel(new BorderLayout(10,10)); p.setBackground(bg); p.setBorder(new EmptyBorder(16,16,16,16));
        reportArea = new JTextArea("Your analysis report will appear here after you analyse a dataset."); reportArea.setEditable(false); reportArea.setFont(new Font(Font.MONOSPACED,0,13)); reportArea.setMargin(new Insets(12,12,12,12));
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT)); actions.setOpaque(false);
        JButton preview = new JButton("Refresh report"); preview.addActionListener(e -> reportArea.setText(buildReport()));
        JButton export = new JButton("Export report (.txt)"); export.addActionListener(e -> exportReport());
        actions.add(preview); actions.add(export); p.add(actions,BorderLayout.NORTH); p.add(new JScrollPane(reportArea),BorderLayout.CENTER); return p;
    }

    private void chooseDataset() {
        JFileChooser chooser = new JFileChooser(); chooser.setDialogTitle("Select a CSV dataset");
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("CSV files (*.csv)","csv"));
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        File file = chooser.getSelectedFile();
        try {
            String csvContent = Files.readString(file.toPath(), StandardCharsets.UTF_8);
            if (csvContent.startsWith("\uFEFF")) csvContent = csvContent.substring(1);
            if (csvContent.isBlank()) throw new IOException("The selected CSV file is empty.");
            char delimiter = detectDelimiter(csvContent);
            List<List<String>> rows = parseCsv(csvContent, delimiter);
            if (rows.size() < 2) throw new IOException("The CSV must contain a header and at least one data row.");
            List<String> headers = rows.get(0);
            int textCol = findColumnExact(headers, List.of("text","content","description","message","post","title","body","tweet","content text"));
            int dateCol = findColumnExact(headers, List.of("created at","created_at","date","timestamp","published","time","created","posted date"));
            int catCol = findColumnExact(headers, List.of("category","categories","label","class","threat category","topic"));
            int idCol = findColumnExact(headers, List.of("id","record_id","post_id","record id","tweet_id"));
            if (textCol < 0) throw new IOException("Could not identify the text column. Expected title, text, content, description, message or post. Found headers: " + headers);
            List<ThreatRecord> temp = new ArrayList<>();
            for (int i=1;i<rows.size();i++) {
                List<String> cells = rows.get(i);
                // Ignore malformed rows rather than shifting values into the wrong columns.
                if (cells.size() != headers.size()) continue;
                String text = cell(cells,textCol);
                if (text.isBlank()) continue;
                String date = dateCol >= 0 ? cell(cells,dateCol) : "Unknown";
                String category = catCol >= 0 ? cell(cells,catCol) : "";
                if (!isPlausibleCategory(category)) category = "";
                String id = idCol >= 0 ? cell(cells,idCol) : String.valueOf(i);
                temp.add(new ThreatRecord(id,date,category,text));
            }
            if (temp.isEmpty()) throw new IOException("No usable records were found. Ensure the CSV has a text, title, content or description column.");
            records.clear(); records.addAll(temp); analysed.clear(); selectedFile = file; datasetName = file.getName();
            fileLabel.setText("Selected file: " + datasetName + "  |  Rows detected: " + records.size());
            statusLabel.setText("Dataset loaded. Click Analyse Data to process it."); statusLabel.setForeground(new Color(255,215,135));
            analyseButton.setEnabled(true); showEmptyState();
            JOptionPane.showMessageDialog(this,"Dataset selected successfully.\n\nFile: "+file.getName()+"\nUsable records detected: "+records.size()+"\n\nClick Analyse Data to generate the report.","Dataset ready",JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,"Could not load CSV:\n"+ex.getMessage(),"Dataset error",JOptionPane.ERROR_MESSAGE);
        }
    }

    private void analyseDataset() {
        if (records.isEmpty()) { JOptionPane.showMessageDialog(this,"Please select a CSV dataset first."); return; }
        analysed.clear();
        for (ThreatRecord r : records) {
            String category = r.category.isBlank() ? classify(r.text) : r.category;
            int score = score(r.text, category);
            analysed.add(new ThreatRecord(r.id,r.date,category,r.text,score,risk(score),threatType(r.text,category),r.categoryProvided));
        }
        populateTable(analysed); updateDashboard();
        reportArea.setText(buildReport()); iocArea.setText(buildIocText());
        statusLabel.setText("Analysis complete • " + analysed.size() + " records analysed"); statusLabel.setForeground(new Color(154,230,180));
        tabs.setSelectedIndex(0);
        showAnalysisDialog();
    }

    private void showAnalysisDialog() {
        String report = buildReport();
        JTextArea area = new JTextArea(report,25,65); area.setEditable(false); area.setFont(new Font(Font.MONOSPACED,0,13)); area.setCaretPosition(0); area.setMargin(new Insets(12,12,12,12));
        JScrollPane scroll = new JScrollPane(area); scroll.setPreferredSize(new Dimension(760,560));
        JOptionPane.showMessageDialog(this,scroll,"Dataset Analysis Report",JOptionPane.INFORMATION_MESSAGE);
    }

    private void updateDashboard() {
        int high=0,medium=0,low=0,missing=0,iocs=0;
        Map<String,Integer> cats=new TreeMap<>();
        for (ThreatRecord r:analysed) {
            if (r.risk.equals("HIGH")) high++; else if(r.risk.equals("MEDIUM")) medium++; else low++;
            if (!r.categoryProvided) missing++;
            if (r.categoryProvided) cats.merge(r.category,1,Integer::sum);
            iocs += extract(r.text).values().stream().mapToInt(Set::size).sum();
        }
        totalValue.setText(""+analysed.size()); highValue.setText(""+high); mediumValue.setText(""+medium); lowValue.setText(""+low); iocValue.setText(""+iocs); missingValue.setText(""+missing);
        String dates = dateRange();
        overview.setText("Dataset: "+datasetName+"\n\nRecords analysed: "+analysed.size()+"\nRecords with category: "+(analysed.size()-missing)+"\nRecords missing category: "+missing+"\nUnique non-empty categories: "+cats.size()+"\nEarliest date: "+dates.split("\\|",-1)[0]+"\nLatest date: "+dates.split("\\|",-1)[1]+"\n\nRISK DISTRIBUTION\nHigh risk: "+high+"\nMedium risk: "+medium+"\nLow risk: "+low+"\nIOC matches: "+iocs+"\n\nCATEGORY COUNTS\n"+categoryCounts()+"\nCategory counts use the original CSV category column only. Missing source categories are not replaced in these counts. Risk classification uses transparent keyword rules; scores are indicative and require analyst validation.");
        categoryChart.setData(categoryData()); monthlyChart.setData(monthlyData());
    }

    private void showEmptyState() {
        if (totalValue == null) return;
        totalValue.setText("—"); highValue.setText("—"); mediumValue.setText("—"); lowValue.setText("—"); iocValue.setText("—"); missingValue.setText("—");
        overview.setText("No analysed dataset yet.\n\nStep 1: Click Select CSV Dataset.\nStep 2: Choose a CSV file from your computer.\nStep 3: Click Analyse Data.\n\nThe dashboard and report will be generated from the selected file. No fixed sample dataset is loaded automatically.");
        categoryChart.setData(Collections.emptyMap()); monthlyChart.setData(Collections.emptyMap());
        tableModel.setRowCount(0); iocArea.setText("No analysis yet."); reportArea.setText("No analysis yet.");
    }

    private void populateTable(List<ThreatRecord> list) {
        tableModel.setRowCount(0);
        for (ThreatRecord r:list) tableModel.addRow(new Object[]{r.id,r.date,r.category,r.threatType,r.risk,r.score,r.text});
    }
    private void filterTable(String query) {
        String q=query.toLowerCase(Locale.ROOT); List<ThreatRecord> found=new ArrayList<>();
        for(ThreatRecord r:analysed) if((r.text+" "+r.category+" "+r.risk+" "+r.threatType+" "+r.id).toLowerCase(Locale.ROOT).contains(q)) found.add(r);
        populateTable(found);
    }

    private String buildReport() {
        if (analysed.isEmpty()) return "No analysis available. Select a CSV and click Analyse Data.";
        Map<String,Integer> cats=new TreeMap<>(); int high=0,med=0,low=0,missing=0;
        for(ThreatRecord r:analysed){if(r.categoryProvided)cats.merge(r.category,1,Integer::sum);if(r.risk.equals("HIGH"))high++;else if(r.risk.equals("MEDIUM"))med++;else low++;if(!r.categoryProvided)missing++;}
        StringBuilder b=new StringBuilder();
        b.append("DATASET ANALYSIS REPORT\n============================================================\n\n");
        b.append("Dataset: ").append(datasetName).append("\nGenerated: ").append(LocalDateTime.now()).append("\n\n");
        b.append("DATASET SUMMARY\nTotal records: ").append(analysed.size()).append("\nRecords with category: ").append(analysed.size()-missing).append("\nRecords missing category: ").append(missing).append("\nUnique non-empty categories: ").append(cats.size()).append("\nEarliest date: ").append(dateRange().split("\\|",-1)[0]).append("\nLatest date: ").append(dateRange().split("\\|",-1)[1]).append("\n\n");
        b.append("RISK DISTRIBUTION\nHigh risk: ").append(high).append("\nMedium risk: ").append(med).append("\nLow risk: ").append(low).append("\n\nCATEGORY COUNTS\n");
        cats.forEach((k,v)->b.append(k).append(": ").append(v).append("\n"));
        b.append("\nINDICATOR SUMMARY\n").append(iocCounts()).append("\nTOP KEYWORD FINDINGS\n").append(topKeywords());
        b.append("\nMETHODOLOGY\nCATEGORY COUNTS use only valid labels from the original category column in the CSV. Records with missing or invalid source categories are counted as missing; inferred threat labels are not added to the source category statistics. Risk scores are heuristic and capped at 100. IOC patterns identify syntactic matches only.\n\nLIMITATIONS\nA keyword or IOC match does not prove malicious activity. Domains, IPs, URLs, hashes and CVE references require validation against trusted threat-intelligence sources. This application does not crawl the dark web or verify live threats.");
        return b.toString();
    }

    private String categoryCounts(){StringBuilder b=new StringBuilder();categoryData().forEach((k,v)->b.append(k).append(": ").append(v).append("\n"));return b.toString();}
    // Category counts intentionally use only the dataset's original category column.
    // Inferred threat labels are shown separately and never mixed into source category statistics.
    private Map<String,Integer> categoryData(){Map<String,Integer> m=new TreeMap<>();for(ThreatRecord r:analysed)if(r.categoryProvided)m.merge(r.category,1,Integer::sum);return m;}
    private Map<String,Integer> monthlyData(){Map<String,Integer> m=new TreeMap<>();for(ThreatRecord r:analysed){String d=normaliseDate(r.date);if(!d.equals("Unknown"))m.merge(d.substring(0,7),1,Integer::sum);}return m;}
    private String dateRange(){List<LocalDate> ds=new ArrayList<>();for(ThreatRecord r:analysed){LocalDate d=parseDate(r.date);if(d!=null)ds.add(d);}if(ds.isEmpty())return "Unknown|Unknown";Collections.sort(ds);return ds.get(0)+"|"+ds.get(ds.size()-1);}

    private String buildIocText(){Map<String,Set<String>> all=emptyIocs();for(ThreatRecord r:analysed)extract(r.text).forEach((k,v)->all.get(k).addAll(v));StringBuilder b=new StringBuilder("INDICATORS OF COMPROMISE (IOC)\n================================================\n");all.forEach((k,v)->{b.append("\n").append(k).append(" ( ").append(v.size()).append(" )\n");if(v.isEmpty())b.append("  None found\n");else v.forEach(x->b.append("  • ").append(x).append("\n"));});return b.toString();}
    private String iocCounts(){Map<String,Set<String>> all=emptyIocs();for(ThreatRecord r:analysed)extract(r.text).forEach((k,v)->all.get(k).addAll(v));StringBuilder b=new StringBuilder();all.forEach((k,v)->b.append(k).append(": ").append(v.size()).append("\n"));return b.toString();}
    private Map<String,Set<String>> emptyIocs(){Map<String,Set<String>> m=new LinkedHashMap<>();for(String k:List.of("IPv4","URLs","Domains","CVE IDs","Hashes"))m.put(k,new LinkedHashSet<>());return m;}
    private Map<String,Set<String>> extract(String s){Map<String,Set<String>> m=emptyIocs();m.get("IPv4").addAll(matches("\\b(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}\\b",s));m.get("URLs").addAll(matches("https?://[^\\s<>\\\"']+",s));m.get("Domains").addAll(matches("\\b(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}\\b",s));m.get("CVE IDs").addAll(matches("\\bCVE-\\d{4}-\\d{4,7}\\b",s.toUpperCase(Locale.ROOT)));m.get("Hashes").addAll(matches("\\b[a-fA-F0-9]{32,64}\\b",s));return m;}
    private Set<String> matches(String regex,String s){Set<String> out=new LinkedHashSet<>();Matcher m=Pattern.compile(regex).matcher(s);while(m.find())out.add(m.group());return out;}
    private String topKeywords(){Map<String,Integer> counts=new LinkedHashMap<>();String[] words={"phishing","malware","ransomware","exploit","credential","password","stolen","leak","botnet","trojan","vulnerability","marketplace","bitcoin","drug"};for(ThreatRecord r:analysed){String t=r.text.toLowerCase(Locale.ROOT);for(String w:words)if(t.contains(w))counts.merge(w,1,Integer::sum);}List<Map.Entry<String,Integer>> list=new ArrayList<>(counts.entrySet());list.sort((a,b)->b.getValue().compareTo(a.getValue()));StringBuilder out=new StringBuilder();for(int i=0;i<Math.min(8,list.size());i++)out.append(list.get(i).getKey()).append(": ").append(list.get(i).getValue()).append(" records\n");if(list.isEmpty())out.append("No configured threat keywords detected.\n");return out.toString();}

    private String classify(String s){String t=s.toLowerCase(Locale.ROOT);if(has(t,"ransomware","ransom","encrypt"))return "Ransomware";if(has(t,"phishing","credential theft","fake login"))return "Phishing";if(has(t,"malware","trojan","rat ","stealer","botnet"))return "Malware";if(has(t,"cve-","vulnerability","exploit","zero-day"))return "Vulnerability";if(has(t,"leak","database dump","stolen data","data breach"))return "Data Leak";if(has(t,"drug","marketplace","bitcoin","crypto"))return "Darknet Market";return "Other";}
    private String threatType(String s,String category){String inferred=classify(s);return inferred.equals("Other")?category:inferred;}
    private int score(String s,String category){String t=(s+" "+category).toLowerCase(Locale.ROOT);int v=0;if(has(t,"ransomware","ransom","encrypt"))v+=35;if(has(t,"exploit","zero-day","remote code execution","cve-"))v+=30;if(has(t,"stolen","leak","credential","password","data breach"))v+=20;if(has(t,"malware","trojan","rat","stealer","botnet"))v+=15;if(has(t,"critical","urgent","actively exploited"))v+=10;return Math.min(100,v);}
    private String risk(int s){return s>=60?"HIGH":s>=30?"MEDIUM":"LOW";}
    private boolean has(String s,String...words){for(String w:words)if(s.contains(w))return true;return false;}

    private void exportReport(){if(analysed.isEmpty()){warnNoAnalysis();return;}JFileChooser c=new JFileChooser();c.setSelectedFile(new File("DarkWebCTI_Analysis_Report.txt"));if(c.showSaveDialog(this)!=JFileChooser.APPROVE_OPTION)return;try{Files.writeString(c.getSelectedFile().toPath(),buildReport(),StandardCharsets.UTF_8);JOptionPane.showMessageDialog(this,"Report saved successfully.");}catch(IOException ex){showError(ex);}}
    private void exportIocs(){if(analysed.isEmpty()){warnNoAnalysis();return;}JFileChooser c=new JFileChooser();c.setSelectedFile(new File("DarkWebCTI_IOCs.csv"));if(c.showSaveDialog(this)!=JFileChooser.APPROVE_OPTION)return;try{StringBuilder b=new StringBuilder("Type,Indicator\n");Map<String,Set<String>> all=emptyIocs();for(ThreatRecord r:analysed)extract(r.text).forEach((k,v)->all.get(k).addAll(v));for(var e:all.entrySet())for(String v:e.getValue())b.append(csv(e.getKey())).append(',').append(csv(v)).append('\n');Files.writeString(c.getSelectedFile().toPath(),b,StandardCharsets.UTF_8);JOptionPane.showMessageDialog(this,"IOC list exported successfully.");}catch(IOException ex){showError(ex);}}
    private String csv(String s){return "\""+s.replace("\"","\"\"")+"\"";}
    private void warnNoAnalysis(){JOptionPane.showMessageDialog(this,"Please select a dataset and click Analyse Data first.");}
    private void showError(Exception ex){JOptionPane.showMessageDialog(this,ex.getMessage(),"Export error",JOptionPane.ERROR_MESSAGE);}

    private int findColumnExact(List<String> headers,List<String> aliases){
        for(int i=0;i<headers.size();i++){String h=normaliseHeader(headers.get(i));for(String alias:aliases)if(h.equals(normaliseHeader(alias)))return i;}
        return -1;
    }
    private String normaliseHeader(String h){return h==null?"":h.replace("\uFEFF","").trim().toLowerCase(Locale.ROOT).replaceAll("[_\\-]+"," ").replaceAll("\\s+"," ");}
    private boolean isPlausibleCategory(String value){
        if(value==null)return false;
        String v=value.trim();
        if(v.isEmpty()||v.length()>70||v.length()<2)return false;
        // Accept readable source labels such as "Anonymity, privacy and security".
        // Reject numbers, code fragments, punctuation noise and IDs.
        return v.matches("[\\p{L}][\\p{L}\\p{M} ,&/()'’\\-]{1,69}")
                && v.chars().filter(Character::isLetter).count()>=2
                && v.split("\\s+").length<=10;
    }
    private String cell(List<String> cells,int index){return index>=0&&index<cells.size()?cells.get(index).trim():"";}
    private char detectDelimiter(String content){String first=content.lines().findFirst().orElse("");char best=',';int max=-1;for(char d:new char[]{',',';','\t'}){int n=0;boolean q=false;for(int i=0;i<first.length();i++){char c=first.charAt(i);if(c=='"')q=!q;else if(c==d&&!q)n++;}if(n>max){max=n;best=d;}}return best;}
    private List<List<String>> parseCsv(String content,char delimiter){
        List<List<String>> rows=new ArrayList<>();List<String> row=new ArrayList<>();StringBuilder cell=new StringBuilder();boolean quoted=false;
        for(int i=0;i<content.length();i++){char c=content.charAt(i);if(c=='"'){if(quoted&&i+1<content.length()&&content.charAt(i+1)=='"'){cell.append('"');i++;}else quoted=!quoted;}
            else if(c==delimiter&&!quoted){row.add(cell.toString());cell.setLength(0);}
            else if((c=='\n'||c=='\r')&&!quoted){if(c=='\r'&&i+1<content.length()&&content.charAt(i+1)=='\n')i++;row.add(cell.toString());cell.setLength(0);if(!(row.size()==1&&row.get(0).isBlank()))rows.add(row);row=new ArrayList<>();}
            else cell.append(c);}
        if(cell.length()>0||!row.isEmpty()){row.add(cell.toString());rows.add(row);}return rows;
    }

    private String normaliseDate(String s){LocalDate d=parseDate(s);return d==null?"Unknown":d.toString();}
    private LocalDate parseDate(String s){if(s==null||s.isBlank())return null;String v=s.trim();try{return LocalDate.parse(v.substring(0,Math.min(10,v.length())));}catch(Exception ignored){}String[] patterns={"M/d/yyyy","MM/dd/yyyy","d-M-yyyy","dd-MM-yyyy","yyyy/MM/dd","yyyy-MM-dd HH:mm:ss","yyyy-MM-dd'T'HH:mm:ss"};for(String p:patterns)try{return LocalDateTime.parse(v,DateTimeFormatter.ofPattern(p)).toLocalDate();}catch(Exception ignored){}for(String p:patterns)try{return LocalDate.parse(v,DateTimeFormatter.ofPattern(p));}catch(Exception ignored){}return null;}

    private JLabel metric(){JLabel l=new JLabel("—");l.setFont(new Font("SansSerif",Font.BOLD,27));l.setForeground(navy);return l;}
    private JPanel metricCard(String name,JLabel value){JPanel p=new JPanel(new GridLayout(2,1,3,5));p.setBackground(Color.WHITE);p.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(new Color(225,231,239)),new EmptyBorder(12,12,12,12)));JLabel n=new JLabel(name);n.setFont(new Font("SansSerif",Font.BOLD,10));n.setForeground(new Color(100,112,128));p.add(n);p.add(value);return p;}
    private JPanel chartBox(JComponent chart){JPanel p=new JPanel(new BorderLayout());p.setBackground(Color.WHITE);p.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(new Color(225,231,239)),new EmptyBorder(8,8,8,8)));p.add(chart);return p;}
    private JPanel wrapPanel(String title,JComponent content){JPanel p=new JPanel(new BorderLayout());p.setBackground(Color.WHITE);p.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(new Color(220,226,234)),title));p.add(content);return p;}
    private void styleButton(JButton b,Color back,Color fore){b.setBackground(back);b.setForeground(fore);b.setFocusPainted(false);b.setFont(new Font("SansSerif",Font.BOLD,12));b.setBorder(new EmptyBorder(9,14,9,14));}

    private class ChartPanel extends JPanel {
        private final String title; private final boolean bars; private Map<String,Integer> data=new TreeMap<>();
        ChartPanel(String title,boolean bars){this.title=title;this.bars=bars;setBackground(Color.WHITE);setPreferredSize(new Dimension(400,245));}
        void setData(Map<String,Integer> d){data=new TreeMap<>(d);repaint();}
        protected void paintComponent(Graphics g){super.paintComponent(g);Graphics2D g2=(Graphics2D)g.create();g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,RenderingHints.VALUE_ANTIALIAS_ON);g2.setColor(navy);g2.setFont(new Font("SansSerif",Font.BOLD,14));g2.drawString(title,14,22);if(data.isEmpty()){g2.setColor(Color.GRAY);g2.drawString("Analyse a dataset to display chart data",20,90);g2.dispose();return;}int left=42,base=getHeight()-42,top=48,plotW=getWidth()-60,plotH=base-top;int max=Math.max(1,Collections.max(data.values()));if(!bars){int x=left,y=top+8,w=plotW-12,h=plotH-12;int total=data.values().stream().mapToInt(Integer::intValue).sum();int start=0;Color[] colors={new Color(39,112,171),new Color(65,151,124),new Color(222,159,66),new Color(155,104,175),new Color(202,91,91),new Color(104,132,160)};int i=0;for(var e:data.entrySet()){int arc=(int)Math.round(360.0*e.getValue()/Math.max(1,total));g2.setColor(colors[i++%colors.length]);g2.fillArc(x,y,w,h,start,arc);start+=arc;}g2.setColor(Color.DARK_GRAY);g2.drawString("Category share",left,base+18);}else{g2.setColor(new Color(100,112,128));g2.drawLine(left,base,getWidth()-12,base);int slot=Math.max(36,plotW/Math.max(1,data.size()));int i=0;for(var e:data.entrySet()){int bh=(int)(plotH*.82*e.getValue()/max);int x=left+8+i*slot;g2.setColor(blue);g2.fillRoundRect(x,base-bh,Math.min(28,slot-5),bh,7,7);g2.setColor(Color.DARK_GRAY);g2.drawString(""+e.getValue(),x+4,base-bh-5);String label=e.getKey();if(label.length()>10)label=label.substring(0,10);g2.drawString(label,x-5,base+16);i++;}}g2.dispose();}
    }
    private static class ThreatRecord {
        final String id,date,category,text; final int score; final String risk,threatType; final boolean categoryProvided;
        ThreatRecord(String id,String date,String category,String text){this(id,date,category,text,0,""," ",category!=null&&!category.isBlank());}
        ThreatRecord(String id,String date,String category,String text,int score,String risk,String threatType,boolean categoryProvided){this.id=id;this.date=date;this.category=category;this.text=text;this.score=score;this.risk=risk;this.threatType=threatType;this.categoryProvided=categoryProvided;}
    }
    public static void main(String[] args){SwingUtilities.invokeLater(()->new Main().setVisible(true));}
}

/*
 * Crimson Authorizer - Automated Authorization Testing for OWASP ZAP.
 *
 * Renico Koen / crimsonwall.com / 2026.
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
 */
package com.crimsonwall.crimsonauthorizer.ui;

import java.awt.AlphaComposite;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DragGestureEvent;
import java.awt.dnd.DragGestureListener;
import java.awt.dnd.DragSource;
import java.awt.dnd.DragSourceAdapter;
import java.awt.dnd.DragSourceDropEvent;
import java.awt.dnd.DragSourceListener;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetAdapter;
import java.awt.dnd.DropTargetDragEvent;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.dnd.DropTargetListener;
import java.awt.image.BufferedImage;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import org.parosproxy.paros.Constant;

/**
 * A JTabbedPane that supports drag-and-drop tab reordering.
 * Based on the Java Swing Tips implementation.
 * Original tab (index 0) is fixed. Unauthenticated tab (index 1, if present) is also fixed.
 * User tabs can be reordered.
 */
public final class DnDTabbedPane extends JTabbedPane {

    private static final long serialVersionUID = 1L;
    private static final int LINE_WIDTH = 3;

    // Maximum ghost image size to prevent memory issues
    private static final int MAX_GHOST_WIDTH = 400;
    private static final int MAX_GHOST_HEIGHT = 200;

    private final GhostGlassPane glassPane;
    private final transient DragSourceListener dragSourceListener;
    private final transient DropTargetListener dropTargetListener;
    private int dragTabIndex = -1;
    private boolean hasInstalledGlassPane = false;

    /**
     * Custom glass pane for rendering the drag ghost image and drop indicator.
     */
    private static class GhostGlassPane extends JPanel {

        private static final long serialVersionUID = 1L;

        private final transient AlphaComposite composite;
        private transient BufferedImage draggingGhost = null;
        private Point location = null;
        private Rectangle lineRect = null;

        GhostGlassPane() {
            setOpaque(false);
            composite = AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.5f);
            setVisible(false);
        }

        void setDraggingGhost(BufferedImage draggingGhost) {
            this.draggingGhost = draggingGhost;
        }

        void setGhostLocation(Point location) {
            this.location = location;
        }

        void setLineRect(Rectangle lineRect) {
            this.lineRect = lineRect;
        }

        void clear() {
            draggingGhost = null;
            location = null;
            lineRect = null;
            setVisible(false);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            if (draggingGhost != null && location != null) {
                g2.setComposite(composite);
                int xx = location.x - draggingGhost.getWidth(this) / 2;
                int yy = location.y - draggingGhost.getHeight(this) / 2;
                g2.drawImage(draggingGhost, xx, yy, this);
            }
            if (lineRect != null) {
                g2.setComposite(AlphaComposite.SrcOver);
                g2.setColor(Color.BLUE);
                g2.fill(lineRect);
            }
            g2.dispose();
        }
    }

    public DnDTabbedPane() {
        super();
        glassPane = new GhostGlassPane();

        dragSourceListener =
                new DragSourceAdapter() {
                    @Override
                    public void dragDropEnd(DragSourceDropEvent e) {
                        glassPane.clear();
                        dragTabIndex = -1;
                        repaint();
                    }
                };

        dropTargetListener =
                new DropTargetAdapter() {
                    @Override
                    public void dragEnter(DropTargetDragEvent e) {
                        e.acceptDrag(DnDConstants.ACTION_MOVE);
                    }

                    @Override
                    public void dragOver(DropTargetDragEvent e) {
                        Point pt = e.getLocation();
                        int targetIndex = indexAtLocation(pt.x, pt.y);

                        if (isFixedTabIndex(targetIndex) || targetIndex == dragTabIndex) {
                            e.rejectDrag();
                            return;
                        }

                        glassPane.setGhostLocation(pt);
                        glassPane.setLineRect(getDropLineRect(targetIndex));
                        glassPane.setVisible(true);
                        glassPane.repaint();
                        e.acceptDrag(DnDConstants.ACTION_MOVE);
                    }

                    @Override
                    public void dropActionChanged(DropTargetDragEvent e) {
                        e.acceptDrag(DnDConstants.ACTION_MOVE);
                    }

                    @Override
                    public void drop(DropTargetDropEvent e) {
                        int targetIndex = getTargetTabIndex(e.getLocation());

                        if (!isFixedTabIndex(dragTabIndex)
                                && !isFixedTabIndex(targetIndex)
                                && dragTabIndex != targetIndex) {
                            convertTab(dragTabIndex, targetIndex);
                            e.dropComplete(true);
                        } else {
                            e.dropComplete(false);
                        }

                        glassPane.clear();
                        dragTabIndex = -1;
                    }
                };

        final DragSource dragSource = DragSource.getDefaultDragSource();
        dragSource.createDefaultDragGestureRecognizer(
                this, DnDConstants.ACTION_MOVE, new DragGestureListener() {
                    @Override
                    public void dragGestureRecognized(DragGestureEvent e) {
                        Point p = e.getDragOrigin();
                        int index = indexAtLocation(p.x, p.y);

                        if (isFixedTabIndex(index)) {
                            return;
                        }

                        dragTabIndex = index;

                        // Ensure glass pane is installed
                        installGlassPane();

                        Rectangle tabBounds = getBoundsAt(index);
                        if (tabBounds == null) return;

                        // Limit ghost image size to prevent memory issues
                        int ghostWidth = Math.min(tabBounds.width, MAX_GHOST_WIDTH);
                        int ghostHeight = Math.min(tabBounds.height, MAX_GHOST_HEIGHT);

                        // Create ghost image - just the tab being dragged (with size limit)
                        BufferedImage ghost = new BufferedImage(
                                ghostWidth, ghostHeight,
                                BufferedImage.TYPE_INT_ARGB);
                        Graphics g = ghost.createGraphics();
                        g.translate(-tabBounds.x, -tabBounds.y);
                        paint(g);
                        g.dispose();

                        glassPane.setDraggingGhost(ghost);
                        glassPane.setGhostLocation(p);
                        glassPane.setVisible(true);

                        // Start the drag
                        e.startDrag(
                                null,
                                ghost,
                                new Point(
                                        tabBounds.width / 2,
                                        tabBounds.height / 2),
                                new TabTransferable(index),
                                dragSourceListener);
                    }
                });

        new DropTarget(this, DnDConstants.ACTION_MOVE, dropTargetListener, true);
    }

    /**
     * Installs the glass pane in the root pane if not already installed.
     */
    private void installGlassPane() {
        if (hasInstalledGlassPane) return;

        try {
            Container ancestor = getTopLevelAncestor();
            if (ancestor instanceof javax.swing.JRootPane) {
                javax.swing.JRootPane rootPane = (javax.swing.JRootPane) ancestor;
                Component currentGlassPane = rootPane.getGlassPane();
                if (currentGlassPane != glassPane) {
                    rootPane.setGlassPane(glassPane);
                }
                hasInstalledGlassPane = true;
            }
        } catch (Exception ex) {
            // Ignore - will retry on next drag
        }
    }

    /**
     * Gets the target tab index based on drop location.
     */
    private int getTargetTabIndex(Point location) {
        int count = getTabCount();
        if (count == 0) return -1;

        // Find the tab at the location
        for (int i = 0; i < count; i++) {
            Rectangle rect = getBoundsAt(i);
            if (rect == null) continue;

            if (rect.contains(location)) {
                int halfWidth = rect.width / 2;
                if (location.x < rect.x + halfWidth) {
                    return i;
                } else {
                    return i + 1;
                }
            }
        }

        // Past all tabs - insert at end
        Rectangle lastRect = getBoundsAt(count - 1);
        if (lastRect != null && location.x > lastRect.x + lastRect.width) {
            return count;
        }

        return -1;
    }

    /**
     * Gets the rectangle for the drop line indicator.
     */
    private Rectangle getDropLineRect(int targetIndex) {
        if (targetIndex < 0 || targetIndex > getTabCount()) {
            return null;
        }

        if (targetIndex == 0) {
            Rectangle rect = getBoundsAt(0);
            if (rect != null) {
                return new Rectangle(rect.x, rect.y, LINE_WIDTH, rect.height);
            }
        } else if (targetIndex >= getTabCount()) {
            Rectangle rect = getBoundsAt(getTabCount() - 1);
            if (rect != null) {
                return new Rectangle(rect.x + rect.width, rect.y, LINE_WIDTH, rect.height);
            }
        } else {
            Rectangle rect = getBoundsAt(targetIndex - 1);
            if (rect != null) {
                return new Rectangle(rect.x + rect.width, rect.y, LINE_WIDTH, rect.height);
            }
        }

        return null;
    }

    /**
     * Moves a tab from one index to another.
     */
    private void convertTab(int prevIndex, int nextIndex) {
        if (prevIndex == nextIndex) return;

        // Clamp nextIndex to valid range (after removal, max index is getTabCount() - 1)
        int minValidIndex = getFirstDraggableIndex();
        if (nextIndex < minValidIndex) nextIndex = minValidIndex;
        if (nextIndex > getTabCount() - 1) nextIndex = getTabCount() - 1;

        String title = getTitleAt(prevIndex);
        Component comp = getComponentAt(prevIndex);
        javax.swing.Icon icon = getIconAt(prevIndex);
        String tip = getToolTipTextAt(prevIndex);

        boolean isSelected = getSelectedIndex() == prevIndex;

        remove(prevIndex);

        // Adjust index if we removed a tab before the target
        int adjustedIndex = nextIndex;
        if (prevIndex < nextIndex) {
            adjustedIndex = nextIndex - 1;
        }

        insertTab(title, icon, comp, tip, adjustedIndex);
        if (isSelected) {
            setSelectedIndex(adjustedIndex);
        }
    }

    /** Transferable for tab data. */
    private static class TabTransferable implements Transferable {

        private static final java.awt.datatransfer.DataFlavor FLAVOR =
                new java.awt.datatransfer.DataFlavor(Integer.class, "Tab Index");
        private final int index;

        TabTransferable(int index) {
            this.index = index;
        }

        @Override
        public java.awt.datatransfer.DataFlavor[] getTransferDataFlavors() {
            return new java.awt.datatransfer.DataFlavor[] {FLAVOR};
        }

        @Override
        public boolean isDataFlavorSupported(java.awt.datatransfer.DataFlavor flavor) {
            return FLAVOR.equals(flavor);
        }

        @Override
        public Object getTransferData(java.awt.datatransfer.DataFlavor flavor) {
            return Integer.valueOf(index);
        }
    }

    @Override
    public void addNotify() {
        super.addNotify();
        installGlassPane();
    }

    /**
     * Checks if a tab index is fixed (should not be draggable).
     * Original (index 0) is always fixed.
     * Unauthenticated (index 1) is fixed if present.
     */
    private boolean isFixedTabIndex(int index) {
        if (index < 0 || index >= getTabCount()) {
            return false;
        }
        // Index 0 (Original) is always fixed
        if (index == 0) {
            return true;
        }
        // Index 1 is fixed only if it's the Unauthenticated tab
        if (index == 1 && getTabCount() > 1) {
            String title = getTitleAt(1);
            // Check if title matches Unauthenticated (localized)
            return title != null && title.equals(
                    Constant.messages.getString("crimsonautorize.label.unauthenticated"));
        }
        return false;
    }

    /**
     * Gets the index of the first draggable tab.
     * Returns 1 if only Original exists (no Unauthenticated tab).
     * Returns 2 if both Original and Unauthenticated exist.
     */
    private int getFirstDraggableIndex() {
        if (getTabCount() > 1) {
            String title = getTitleAt(1);
            if (title != null && title.contains("Unauthenticated")) {
                return 2; // Unauthenticated exists, user tabs start at 2
            }
        }
        return 1; // Only Original exists, user tabs start at 1
    }
}
